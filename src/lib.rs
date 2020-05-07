use adnl::{
    common::{
        add_object_to_map, deserialize_bundle, get256, hash, KeyId, KeyOption, 
        Query, QueryResult, serialize, serialize_append, Subscriber, UpdatedAt, Version
    }, 
    node::{AddressCache, AdnlNode, IpAddress}
};
use rldp::{RaptorqDecoder, RaptorqEncoder, RldpNode};
use sha2::Digest;
use std::{sync::{Arc, atomic::{AtomicBool, AtomicU32, Ordering}}, time::Duration};
use ton_api::{
    IntoBoxed, 
    ton::{
        self, TLObject, 
        adnl::id::short::Short as AdnlShortId, 
        fec::{Type as FecType, type_::RaptorQ as FecTypeRaptorQ}, 
        overlay::{
            Broadcast, Certificate as OverlayCertificate, Message as OverlayMessageBoxed, 
            Nodes as OverlayNodeInfosWrapped,
            broadcast::{
                Broadcast as BroadcastOrd, BroadcastFec, id::Id as BroadcastOrdId, 
                tosign::ToSign as BroadcastToSign
            },
            broadcast_fec::{id::Id as BroadcastFecId, partid::PartId as BroadcastFecPartId}, 
            message::Message as OverlayMessage, 
            node::{Node as OverlayNodeInfo, tosign::ToSign as OverlayNodeInfoToSign},
            nodes::Nodes as OverlayNodeInfos
        },
        pub_::publickey::Overlay, rpc::overlay::{GetRandomPeers, Query as OverlayQuery},
        ton_node::shardpublicoverlayid::ShardPublicOverlayId
    }
};
use ton_types::{fail, Result};

const TARGET: &str = "overlay";

struct BroadcastReceiver {
    data: lockfree::queue::Queue<Vec<u8>>,
    subscribers: lockfree::queue::Queue<Arc<tokio::sync::Barrier>>,
    synclock: AtomicU32,
}

impl BroadcastReceiver {

    fn push(receiver: &Arc<Self>, data: Vec<u8>) {
        let receiver = receiver.clone();
        tokio::spawn(
            async move {
                receiver.data.push(data);
                while receiver.synclock.load(Ordering::Relaxed) > 0 {
                    if let Some(subscriber) = receiver.subscribers.pop() {
                        subscriber.wait().await;
                        break;
                    } else {
                        tokio::task::yield_now().await;
                    }
                }                
            }
        );
    }

    async fn pop(&self) -> Result<Vec<u8>> {
        self.synclock.fetch_add(1, Ordering::Relaxed);
        loop {
            if let Some(data) = self.data.pop() {
                self.synclock.fetch_sub(1, Ordering::Relaxed);
                return Ok(data)
            } else {
                let subscriber = Arc::new(tokio::sync::Barrier::new(2));
                self.subscribers.push(subscriber.clone());  
                subscriber.wait().await;
            }
        }
    }

}

pub type OverlayId = [u8; 32];
pub type OverlayShortId = KeyId;
pub type PrivateOverlayShortId = KeyId;

/// Overlay utilities
pub struct OverlayUtils;

impl OverlayUtils {

    /// Calculate overlay ID for shard
    pub fn calc_overlay_id(
        workchain: i32, 
        _shard: i64, 
        zero_state_file_hash: &[u8; 32]
    ) -> Result<OverlayId> {
        let overlay = ShardPublicOverlayId {
            shard: 1i64 << 63,
            workchain,
            zero_state_file_hash: ton::int256(zero_state_file_hash.clone())
        };
        hash(overlay)
    }

    /// Calculate overlay short ID for shard
    pub fn calc_overlay_short_id(
        workchain: i32, 
        shard: i64,
        zero_state_file_hash: &[u8; 32]
    ) -> Result<Arc<OverlayShortId>> {
        let overlay = Overlay {
            name: ton::bytes(
                Self::calc_overlay_id(workchain, shard, zero_state_file_hash)?.to_vec()
            )
        };
        Ok(OverlayShortId::from_data(hash(overlay)?))
    }

    pub fn calc_private_overlay_short_id(
        first_block: &ton_api::ton::catchain::FirstBlock
    ) -> Result<Arc<PrivateOverlayShortId>> {
        let key = Overlay { 
            name: ton::bytes(serialize(first_block)?) 
        };
        Ok(PrivateOverlayShortId::from_data(hash(key)?))
    }
}

struct OverlayShard {
    adnl: Arc<AdnlNode>,
    message_prefix: Vec<u8>,
    neighbours: AddressCache,
    overlay_id: Arc<OverlayShortId>,
    peers: AddressCache,
    query_prefix: Vec<u8>,
    received: Arc<BroadcastReceiver>,
    transfers_fec: lockfree::map::Map<[u8; 32], RecvTransferFec>
}

impl OverlayShard {

    const SPINNER: u32 = 100; // Milliseconds
    const TIMEOUT_BROADCAST: u64 = 3; // Seconds
    const FLAG_BCAST_ANY_SENDER: i32 = 1;

    fn calc_fec_part_to_sign(
        data_hash: &[u8; 32],
        data_size: i32, 
        date: i32, 
        flags: i32,
        params: &FecTypeRaptorQ,
        part: &[u8],
        seqno: i32,
        src: [u8; 32]
    ) -> Result<Vec<u8>> {

        let broadcast_id = BroadcastFecId {
            src: ton::int256(src),
            type_: ton::int256(hash(params.clone())?),
            data_hash: ton::int256(data_hash.clone()),
            size: data_size,
            flags
        };
        let broadcast_hash = hash(broadcast_id)?;
        let part_data_hash = sha2::Sha256::digest(part);
        let part_data_hash = arrayref::array_ref!(part_data_hash.as_slice(), 0, 32).clone();

        let part_id = BroadcastFecPartId {
            broadcast_hash: ton::int256(broadcast_hash),
            data_hash: ton::int256(part_data_hash),
            seqno
        };
        let part_hash = hash(part_id)?;

        let to_sign = BroadcastToSign {
            hash: ton::int256(part_hash),
            date
        }.into_boxed();
        serialize(&to_sign)

    }

    fn create_fec_recv_transfer(
        overlay_shard: &Arc<Self>, 
        bcast: &Box<BroadcastFec>
    ) -> Result<RecvTransferFec> {

        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type
        } else {
            fail!("Unsupported FEC type")
        };
                        
        let overlay_shard = overlay_shard.clone();
        let transfer_id = get256(&bcast.data_hash).clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
        let mut decoder = RaptorqDecoder::with_params(fec_type.as_ref().clone());

        tokio::spawn(
            async move {
                while let Some(bcast) = reader.recv().await {
                    match Self::process_fec_broadcast(&mut decoder, &bcast) {
                        Err(err) => log::warn!(
                            target: TARGET, 
                            "Error when receiving overlay {} broadcast: {}",
                            overlay_shard.overlay_id,
                            err
                        ),
                        Ok(Some(data)) => 
                            BroadcastReceiver::push(&overlay_shard.received, data),
                        Ok(None) => continue
                    }
                    break;
                }   
                if let Some(transfer) = overlay_shard.transfers_fec.get(&transfer_id) {
                    transfer.val().completed.store(true, Ordering::Relaxed)
                }
                // Graceful close
                reader.close();
                while let Some(_) = reader.recv().await { 
                }
            }
        );

        let ret = RecvTransferFec {
            completed: AtomicBool::new(false),
            sender,
            updated_at: UpdatedAt::new()
        };
        Ok(ret)

    }

    fn create_fec_send_transfer(overlay_shard: &Arc<Self>, data: &[u8], key: &Arc<KeyOption>) {

        let overlay_shard_clone = overlay_shard.clone();
        let key_clone = key.clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();

        let data_size = data.len() as u32;
        let data_hash = sha2::Sha256::digest(data);
        let data_hash = arrayref::array_ref!(data_hash.as_slice(), 0, 32).clone();
        let mut transfer = SendTransferFec {
            data_hash,
            encoder: RaptorqEncoder::with_data(data),
            seqno: 0
        };
        let max_seqno = (data_size / transfer.encoder.params().symbol_size as u32 + 1) * 2;

        tokio::spawn(
            async move {
                while transfer.seqno <= max_seqno {
                    for _ in 0..4 {
                        let result = overlay_shard_clone
                            .prepare_fec_broadcast(&mut transfer, &key_clone)
                            .and_then(
                                |data| {
                                    sender.send(data)?; 
                                    Ok(())
                                }
                            );
                        if let Err(err) = result {    
                            log::warn!(
                                target: TARGET, 
                                "Error when sending overlay {} broadcast: {}",
                                overlay_shard_clone.overlay_id,
                                err
                            );
                            return;
                        }
                    }
                    tokio::time::delay_for(Duration::new(0, Self::SPINNER)).await;            
                }   
            }
        );

        let overlay_shard = overlay_shard.clone();
        let key = key.id().clone();

        tokio::spawn(
            async move {
                while let Some(buf) = reader.recv().await {
                    if let Err(err) = overlay_shard.distribute_broadcast(&buf, &key).await {
                        log::warn!(
                            target: TARGET, 
                            "Error when sending overlay {} FEC broadcast: {}",
                            overlay_shard.overlay_id,
                            err
                        );
                    }
                }   
                // Graceful close
                reader.close();
                while let Some(_) = reader.recv().await { 
                }
            }
        );

    }

    async fn distribute_broadcast(&self, data: &[u8], key: &Arc<KeyId>) -> Result<()> {
        log::trace!(
            target: TARGET,
            "Broadcast {} bytes to overlay {}, {} neighbours",
            data.len(),
            self.overlay_id, 
            self.neighbours.count()
        );
        let (mut iter, mut neighbour) = self.neighbours.first();
        while let Some(dst) = neighbour {
            self.adnl.send_custom(&dst, key, data).await?;
            neighbour = self.neighbours.next(&mut iter);
        }
        Ok(())
    }

    fn prepare_fec_broadcast(
        &self, 
        transfer: &mut SendTransferFec, 
        key: &Arc<KeyOption>
    ) -> Result<Vec<u8>> {

        let chunk = transfer.encoder.encode(&mut transfer.seqno)?;
        let date = Version::get();
        let signature = Self::calc_fec_part_to_sign(
            &transfer.data_hash,
            transfer.encoder.params().data_size, 
            date, 
            Self::FLAG_BCAST_ANY_SENDER,
            transfer.encoder.params(),
            &chunk,
            transfer.seqno as i32,
            [0u8; 32]
        )?;
        let signature = key.sign(&signature)?;

        let bcast = BroadcastFec {
            src: key.into_tl_public_key()?,
            certificate: OverlayCertificate::Overlay_EmptyCertificate,
            data_hash: ton::int256(transfer.data_hash.clone()),
            data_size: transfer.encoder.params().data_size, 
            flags: Self::FLAG_BCAST_ANY_SENDER,
            data: ton::bytes(chunk),
            seqno: transfer.seqno as i32, 
            fec: transfer.encoder.params().clone().into_boxed(),
            date,
            signature: ton::bytes(signature.to_vec())
        }.into_boxed();

        transfer.seqno += 1;
        let mut buf = self.message_prefix.clone();
        serialize_append(&mut buf, &bcast)?;
        Ok(buf)

    }

    fn process_fec_broadcast(
        decoder: &mut RaptorqDecoder, 
        bcast: &Box<BroadcastFec>
    ) -> Result<Option<Vec<u8>>> {
           
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type
        } else {
            fail!("Unsupported FEC type")
        };

        let src_key = KeyOption::from_tl_public_key(&bcast.src)?;
        let src = if (bcast.flags & Self::FLAG_BCAST_ANY_SENDER) != 0 {
            [0u8; 32]
        } else {                           
            src_key.id().data().clone()
        };

        let signature = Self::calc_fec_part_to_sign(
            get256(&bcast.data_hash),
            bcast.data_size, 
            bcast.date,
            bcast.flags,
            fec_type,
            &bcast.data,
            bcast.seqno,
            src
        )?;
        src_key.verify(&signature, &bcast.signature.0)?;

        let ret = decoder.decode(bcast.seqno as u32, &bcast.data);
        if let Some(ret) = &ret {
            if ret.len() != bcast.data_size as usize {
                fail!("Expected {} bytes, but received {}", bcast.data_size, ret.len())
            }
        }
        Ok(ret)

    }

    fn receive_fec_broadcast(overlay_shard: &Arc<Self>, bcast: Box<BroadcastFec>) -> Result<()> {
        for transfer in overlay_shard.transfers_fec.iter() {
            if transfer.val().updated_at.is_expired(Self::TIMEOUT_BROADCAST) {
                overlay_shard.transfers_fec.remove(transfer.key());
            }
        }
        let transfer_id = &bcast.data_hash.0;
        let transfer = if let Some(transfer) = overlay_shard.transfers_fec.get(transfer_id) {
            transfer
        } else {
            add_object_to_map(
                &overlay_shard.transfers_fec,
                transfer_id.clone(),
                || Self::create_fec_recv_transfer(overlay_shard, &bcast)
            )?;
            if let Some(transfer) = overlay_shard.transfers_fec.get(transfer_id) {
                transfer
            } else {
                return Ok(())
            }
        };
        let transfer = transfer.val();
        if !transfer.completed.load(Ordering::Relaxed) {
            transfer.sender.send(bcast)?;
            transfer.updated_at.refresh();
        }
        Ok(())
    }

    async fn send_broadcast(&self, data: &[u8], key: &Arc<KeyOption>) -> Result<()> {

        let date = Version::get();
        let data_hash = sha2::Sha256::digest(data);
        let data_hash = arrayref::array_ref!(data_hash.as_slice(), 0, 32).clone();

        let bcast_id = BroadcastOrdId {
            src: ton::int256([0u8; 32]),
            data_hash: ton::int256(data_hash),
            flags: Self::FLAG_BCAST_ANY_SENDER
        };
        let data_hash = hash(bcast_id)?;

        let to_sign = BroadcastToSign {
            hash: ton::int256(data_hash),
            date
        }.into_boxed();
        let signature = key.sign(&serialize(&to_sign)?)?;
        let bcast = BroadcastOrd {
            src: key.into_tl_public_key()?,
            certificate: OverlayCertificate::Overlay_EmptyCertificate,
            flags: Self::FLAG_BCAST_ANY_SENDER,
            data: ton::bytes(data.to_vec()),
            date: Version::get(),
            signature: ton::bytes(signature.to_vec())
        }.into_boxed();                                   
/*
pub struct Broadcast {
    pub src: crate::ton::PublicKey,
    pub certificate: crate::ton::overlay::Certificate,
    pub flags: crate::ton::int,
    pub data: crate::ton::bytes,
    pub date: crate::ton::int,
    pub signature: crate::ton::bytes,
}
*/
        let mut buf = self.message_prefix.clone();
        serialize_append(&mut buf, &bcast)?;
        self.distribute_broadcast(&buf, key.id()).await

    } 

    fn update_neighbours(&self, n: u32) -> Result<()> {
        self.peers.random_set(&self.neighbours, n)
    }

}

struct RecvTransferFec {
    completed: AtomicBool,
    sender: tokio::sync::mpsc::UnboundedSender<Box<BroadcastFec>>,
    updated_at: UpdatedAt
}

struct SendTransferFec {
    data_hash: [u8; 32],
    encoder: RaptorqEncoder,
    seqno: u32
}

/// Overlay Node
pub struct OverlayNode {
    adnl: Arc<AdnlNode>,
    known_peers: AddressCache, 
    node_key: Arc<KeyOption>, 
    shards: lockfree::map::Map<Arc<OverlayShortId>, Arc<OverlayShard>>,
    zero_state_file_hash: [u8; 32]
}

impl OverlayNode {

    const MAX_PEERS: u32 = 65536;
    const MAX_SHARD_NEIGHBOURS: u32 = 5;
    const MAX_SHARD_PEERS: u32 = 20;
    const MAX_SIZE_ORDINARY_BROADCAST: usize = 768;

    /// Constructor 
    pub fn with_adnl_node_and_zero_state(
        adnl: Arc<AdnlNode>, 
        zero_state_file_hash: &[u8; 32],
        key_tag: usize
    ) -> Result<Arc<Self>> {    
        let node_key = adnl.key_by_tag(key_tag)?;
        let ret = Self { 
            adnl,
            known_peers: AddressCache::with_limit(Self::MAX_PEERS),
            node_key,
            shards: lockfree::map::Map::new(),
            zero_state_file_hash: zero_state_file_hash.clone()
        };
        Ok(Arc::new(ret))
    }

    /// Add overlay peer 
    pub fn add_peer(
        &self, 
        peer_ip_address: &IpAddress, 
        peer_key: &Arc<KeyOption>
    ) -> Result<Arc<KeyId>> {
        let ret = self.adnl.add_peer(self.node_key.id(), peer_ip_address, peer_key)?;
        self.known_peers.put(ret.clone())?;
        Ok(ret)
    }

    /// Add shard
    pub fn add_shard(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        log::debug!(
            target: TARGET,
            "Add shard {} to overlay, {} known peers", 
            overlay_id,
            self.known_peers.count()
        );
        add_object_to_map(
            &self.shards,
            overlay_id.clone(), 
            || {
                let message_prefix = OverlayMessage {
                    overlay: ton::int256(overlay_id.data().clone())
                }.into_boxed();
                let query_prefix = OverlayQuery {
                    overlay: ton::int256(overlay_id.data().clone())
                };
                let shard = OverlayShard {
                    adnl: self.adnl.clone(),
                    message_prefix: serialize(&message_prefix)?,
                    neighbours: AddressCache::with_limit(Self::MAX_SHARD_NEIGHBOURS), 
                    overlay_id: overlay_id.clone(),
                    query_prefix: serialize(&query_prefix)?,
                    peers: AddressCache::with_limit(Self::MAX_SHARD_PEERS),
                    received: Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0)
                        }
                    ),
                    transfers_fec: lockfree::map::Map::new()
                };
                self.known_peers.random_set(&shard.peers, Self::MAX_SHARD_PEERS)?;
                shard.update_neighbours(Self::MAX_SHARD_NEIGHBOURS)?;
                Ok(Arc::new(shard))
            }
        )
    }

    /// Broadcast message 
    pub async fn broadcast(&self, overlay_id: &Arc<OverlayShortId>, data: &[u8]) -> Result<u32> {
        log::trace!(target: TARGET, "Broadcast {} bytes", data.len());
        if let Some(shard) = self.shards.get(overlay_id) {
            if data.len() <= Self::MAX_SIZE_ORDINARY_BROADCAST {
                shard.val().send_broadcast(data, &self.node_key).await?
            } else {
                OverlayShard::create_fec_send_transfer(shard.val(), data, &self.node_key)
            }
            Ok(shard.val().neighbours.count())
        } else {
            fail!("Trying broadcast to unknown overlay {}", overlay_id)
        }     
    } 

    /// Calculate overlay short ID for shard
    pub fn calc_overlay_short_id(
        &self, 
        workchain: i32, 
        shard: i64 
    ) -> Result<Arc<OverlayShortId>> {            
        OverlayUtils::calc_overlay_short_id(workchain, shard, &self.zero_state_file_hash)
    }

    /// Get query prefix
    pub fn get_query_prefix(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Vec<u8>> {
        if let Some(shard) = self.shards.get(overlay_id) {
            Ok(shard.val().query_prefix.clone())
        } else {
            fail!("Getting query prefix of unknown overlay {}", overlay_id)
        }
    }
    
    /// overlay.GetRandomPeers
    pub async fn get_random_peers(
        &self, 
        dst: &Arc<KeyId>, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<Vec<OverlayNodeInfo>>> {
        let version = Version::get();
        let our_node = OverlayNodeInfoToSign {
            id: AdnlShortId {
                id: ton::int256(self.node_key.id().data().clone())
            },
            overlay: ton::int256(overlay_id.data().clone()),
            version 
        }.into_boxed();     
        let our_node = OverlayNodeInfo {
            id: self.node_key.into_tl_public_key()?,
            overlay: ton::int256(overlay_id.data().clone()),
            signature: ton::bytes(self.node_key.sign(&serialize(&our_node)?)?.to_vec()),
            version
        };     
        let peers = GetRandomPeers {
            peers: OverlayNodeInfos {
                nodes: vec![our_node].into()
            }
        };
        let query = TLObject::new(peers);
        let answer = self.query(dst, &query, overlay_id).await?;
        if let Some(answer) = answer {
            let answer: OverlayNodeInfosWrapped = Query::parse(answer, &query)?;
            Ok(Some(answer.only().nodes.0))
        } else {
            Ok(None)    
        }
    }

    /// Send query via RLDP
    pub async fn query_via_rldp(
        &self, 
        rldp: &Arc<RldpNode>,
        dst: &Arc<KeyId>, 
        data: &[u8],
        max_answer_size: Option<i64>
    ) -> Result<Option<Vec<u8>>> {
        rldp.query(dst, self.node_key.id(), data, max_answer_size).await
    }

    /// Wait for broadcast
    pub async fn wait_for_broadcast(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Vec<u8>> {
        if let Some(overlay_shard) = self.shards.get(overlay_id) {
            overlay_shard.val().received.pop().await
        } else {
            fail!("Waiting for broadcast in unknown overlay {}", overlay_id)
        }
    }

    async fn query(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TLObject,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<TLObject>> {
        if let Some(shard) = self.shards.get(overlay_id) {
            self.adnl.query_with_prefix(
                dst, 
                self.node_key.id(),
                Some(&shard.val().query_prefix), 
                query
            ).await
        } else {
            fail!("Sending query to unknown overlay {}", overlay_id)
        }
    }

}

impl Subscriber for OverlayNode {
                                                           
    fn try_consume_custom(&self, data: &[u8]) -> Result<bool> {
        let mut bundle = deserialize_bundle(data)?;
        if bundle.len() != 2 {
            return Ok(false)
        }
        let overlay_id = match bundle.remove(0).downcast::<OverlayMessageBoxed>() {
            Ok(msg) => OverlayShortId::from_data(msg.overlay().0),
            Err(msg) => {
                log::debug!(target: TARGET, "Unsupported overlay message {:?}", msg);
                return Ok(false)
            }
        };
        let overlay_shard = if let Some(overlay_shard) = self.shards.get(&overlay_id) {
            overlay_shard
        } else {
            log::debug!(target: TARGET, "Message to unknown overlay {}", overlay_id);
            return Ok(false)
        };
        match bundle.remove(0).downcast::<Broadcast>() {
            Ok(Broadcast::Overlay_BroadcastFec(bcast)) => {
                OverlayShard::receive_fec_broadcast(overlay_shard.val(), bcast)?;
                Ok(true)
            },
            Ok(bcast) =>  {
                log::debug!(
                    target: TARGET, 
                    "Unsupported overlay broadcast message {:?}", 
                    bcast
                );
                Ok(false)
            },
            Err(msg) => {
                log::debug!(target: TARGET, "Unsupported overlay message {:?}", msg);
                Ok(false)
            }
        }
    }

    fn try_consume_query(&self, object: TLObject) -> Result<QueryResult> {
        println!("try_consume_query OVERLAY {:?}", object);
        Ok(QueryResult::Rejected(object))
    }    

    fn try_consume_query_bundle(&self, objects: Vec<TLObject>) -> Result<QueryResult> {
        println!("try_consume_query_bundle OVERLAY {:?}", objects);
        Ok(QueryResult::RejectedBundle(objects))
    }    

}
