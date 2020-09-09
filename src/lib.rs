use adnl::{
    common::{
        add_object_to_map, add_object_to_map_with_update, AdnlPeers, deserialize_bundle, 
        get256, hash, hash_boxed, KeyId, KeyOption, Query, QueryResult, serialize, 
        serialize_append, Subscriber, UpdatedAt, Version
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
        catchain::{
            FirstBlock as CatchainFirstBlock, Update as CatchainBlockUpdateBoxed, 
            blockupdate::BlockUpdate as CatchainBlockUpdate
        },
        fec::{Type as FecType, type_::RaptorQ as FecTypeRaptorQ}, 
        overlay::{
            Broadcast, Certificate as OverlayCertificate, Message as OverlayMessageBoxed, 
            Nodes as NodesBoxed,
            broadcast::{
                Broadcast as BroadcastOrd, BroadcastFec, id::Id as BroadcastOrdId, 
                tosign::ToSign as BroadcastToSign
            },
            broadcast_fec::{id::Id as BroadcastFecId, partid::PartId as BroadcastFecPartId}, 
            message::Message as OverlayMessage, node::{Node, tosign::ToSign as NodeToSign},
            nodes::Nodes
        },
        pub_::publickey::{Ed25519, Overlay}, 
        rpc::overlay::{GetRandomPeers, Query as OverlayQuery}, 
        ton_node::shardpublicoverlayid::ShardPublicOverlayId,
        validator_session::{
            BlockUpdate as ValidatorSessionBlockUpdateBoxed, 
            blockupdate::BlockUpdate as ValidatorSessionBlockUpdate
        }
    }
};
use ton_types::{error, fail, Result};

const TARGET: &str = "overlay";

pub fn build_overlay_node_info(
    overlay: &Arc<OverlayShortId>,  
    version: i32, 
    key: &str, 
    signature: &str
) -> Result<Node> {
    let key = base64::decode(key)?;
    if key.len() != 32 {
        fail!("Bad public key length")
    }
    let signature = base64::decode(signature)?;
    let node = Node {
        id: Ed25519 {
            key: ton::int256(arrayref::array_ref!(&key, 0, 32).clone())
        }.into_boxed(),
        overlay: ton::int256(overlay.data().clone()),
        version,
        signature: ton::bytes(signature)
    };
    Ok(node)
}

struct BroadcastReceiver<T> {
    data: lockfree::queue::Queue<T>,
    subscribers: lockfree::queue::Queue<Arc<tokio::sync::Barrier>>,
    synclock: AtomicU32,
}

impl <T: Send + 'static> BroadcastReceiver<T> {

    fn push(receiver: &Arc<Self>, data: T) {
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

    async fn pop(&self) -> Result<T> {
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

    pub fn calc_private_overlay_short_id(first_block: &CatchainFirstBlock) -> Result<Arc<PrivateOverlayShortId>> {
        let serialized_first_block = serialize(first_block)?;
        let overlay_id = Overlay { name : serialized_first_block.into() };
        let id = hash_boxed(&overlay_id.into_boxed())?;
        Ok(PrivateOverlayShortId::from_data(id))
    }

    /// Verify node info
    pub fn verify_node(overlay_id: &Arc<OverlayShortId>, node: &Node) -> Result<()> {
        let key = KeyOption::from_tl_public_key(&node.id)?; 
        if get256(&node.overlay) != overlay_id.data() {
            fail!(
                "Got peer {} with wrong overlay {}, expected {}",
                key.id(),
                base64::encode(get256(&node.overlay)),
                overlay_id
            )
        }
        let node_to_sign = NodeToSign {
            id: AdnlShortId {
                id: ton::int256(key.id().data().clone())
            },
            overlay: node.overlay.clone(),
            version: node.version 
        }.into_boxed();    
        if let Err(e) = key.verify(&serialize(&node_to_sign)?, &node.signature) {
            fail!("Got peer {} with bad signature: {}", key.id(), e)
        }
        Ok(())
    }

}

type BroadcastId = [u8; 32];
type CatchainReceiver = BroadcastReceiver<
    (CatchainBlockUpdate, ValidatorSessionBlockUpdate, Arc<KeyId>)
>;

struct OverlayShard {
    adnl: Arc<AdnlNode>,
    message_prefix: Vec<u8>,
    known_peers: AddressCache,
    neighbours: AddressCache,
    nodes: lockfree::map::Map<Arc<KeyId>, Node>,
    overlay_id: Arc<OverlayShortId>,
    overlay_key: Option<Arc<KeyId>>,
    past_broadcasts: lockfree::map::Map<BroadcastId, ()>,
    purge_broadcasts: lockfree::queue::Queue<BroadcastId>,
    purge_count: AtomicU32,
    query_prefix: Vec<u8>,
    random_peers: AddressCache,
    received_catchain: Option<Arc<CatchainReceiver>>,
    received_rawbytes: Arc<BroadcastReceiver<(Vec<u8>, Arc<KeyId>)>>,
    transfers_fec: lockfree::map::Map<BroadcastId, RecvTransferFec>
}

impl OverlayShard {

    const SPINNER: u64 = 10;              // Milliseconds
    const TIMEOUT_BROADCAST: u64 = 3;     // Seconds
    const FLAG_BCAST_ANY_SENDER: i32 = 1;

    fn calc_broadcast_id(&self, data: &[u8]) -> Result<Option<BroadcastId>> {
        let bcast_id = sha2::Sha256::digest(data);
        let bcast_id = arrayref::array_ref!(bcast_id.as_slice(), 0, 32);
        let added = add_object_to_map(
            &self.past_broadcasts,
            bcast_id.clone(),
            || Ok(())
        )?;
        if !added {
            Ok(None)
        } else {
            Ok(Some(bcast_id.clone()))
        }
    }

    fn calc_broadcast_to_sign(
        data: &[u8],
        date: i32,
        src: [u8; 32]
    ) -> Result<Vec<u8>> {
       let data_hash = sha2::Sha256::digest(data);
       let data_hash = arrayref::array_ref!(data_hash.as_slice(), 0, 32).clone();        
       let bcast_id = BroadcastOrdId {
            src: ton::int256(src),
            data_hash: ton::int256(data_hash),
            flags: Self::FLAG_BCAST_ANY_SENDER
        };
        let data_hash = hash(bcast_id)?;
        let to_sign = BroadcastToSign {
            hash: ton::int256(data_hash),
            date
        }.into_boxed();
        serialize(&to_sign)
    }

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
                        
        let overlay_shard_recv = overlay_shard.clone();
        let bcast_id_recv = get256(&bcast.data_hash).clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
        let mut decoder = RaptorqDecoder::with_params(fec_type.as_ref().clone());
        let overlay_shard_wait = overlay_shard_recv.clone();
        let bcast_id_wait = bcast_id_recv.clone();

        tokio::spawn(
            async move {
                let mut source = None;
                while let Some(bcast) = reader.recv().await {
                    match Self::process_fec_broadcast(&mut decoder, &mut source, &bcast) {
                        Err(err) => log::warn!(
                            target: TARGET, 
                            "Error when receiving overlay {} broadcast: {}",
                            overlay_shard_recv.overlay_id,
                            err
                        ),
                        Ok(Some((data, source))) => BroadcastReceiver::push(
                            &overlay_shard_recv.received_rawbytes, 
                            (data, source)
                        ),
                        Ok(None) => continue
                    }
                    break;
                }   
                if let Some(transfer) = overlay_shard_recv.transfers_fec.get(&bcast_id_recv) {
                    transfer.val().completed.store(true, Ordering::Relaxed)
                }
                overlay_shard_recv.purge_count.fetch_add(1, Ordering::Relaxed);
                overlay_shard_recv.purge_broadcasts.push(bcast_id_recv);
                // Graceful close
                reader.close();
                while let Some(_) = reader.recv().await { 
                }
            }
        );

        tokio::spawn(
            async move {
                loop {
                    tokio::time::delay_for(
                        Duration::from_millis(Self::TIMEOUT_BROADCAST * 100)
                    ).await;
                    match overlay_shard_wait.transfers_fec.get(&bcast_id_wait) {
                        Some(transfer) => {
                            if transfer.val().updated_at.is_expired(Self::TIMEOUT_BROADCAST) {
                                overlay_shard_wait.transfers_fec.remove(&bcast_id_wait);
                                break
                            }
                        },
                        _ => break
                    }
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

    fn create_fec_send_transfer(
        overlay_shard: &Arc<Self>, 
        data: &[u8], 
        key: &Arc<KeyOption>
    ) -> Result<()> {

        let overlay_shard_clone = overlay_shard.clone();
        let key_clone = key.clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();

        let data_size = data.len() as u32;
        let bcast_id = if let Some(bcast_id) = overlay_shard.calc_broadcast_id(data)? {
            bcast_id
        } else {
            return Ok(())
        };
        let mut transfer = SendTransferFec {
            bcast_id: bcast_id.clone(),
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
                    tokio::time::delay_for(Duration::from_millis(Self::SPINNER)).await;            
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
                overlay_shard.purge_count.fetch_add(1, Ordering::Relaxed);
                overlay_shard.purge_broadcasts.push(bcast_id);
                // Graceful close
                reader.close();
                while let Some(_) = reader.recv().await { 
                }
            }
        );
        Ok(())

    }

    async fn distribute_broadcast(&self, data: &[u8], key: &Arc<KeyId>) -> Result<()> {
        log::trace!(
            target: TARGET,
            "Broadcast {} bytes to overlay {}, {} neighbours",
            data.len(),
            self.overlay_id, 
            self.neighbours.count()
        );
        let mut peers: Option<AdnlPeers> = None;
        let (mut iter, mut neighbour) = self.neighbours.first();
        while let Some(dst) = neighbour {               
            let peers = if let Some(peers) = &mut peers {
                peers.set_other(dst);
                peers
            } else {
                peers.get_or_insert_with(|| AdnlPeers::with_keys(key.clone(), dst))
            };
            self.adnl.send_custom(data, peers).await?;
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
            &transfer.bcast_id,
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
            data_hash: ton::int256(transfer.bcast_id.clone()),
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
        source: &mut Option<Arc<KeyId>>,
        bcast: &Box<BroadcastFec>
    ) -> Result<Option<(Vec<u8>, Arc<KeyId>)>> {
           
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type
        } else {
            fail!("Unsupported FEC type")
        };

        let src_key = KeyOption::from_tl_public_key(&bcast.src)?;
        if let Some(source) = source {
            if source != src_key.id() {
                fail!("Same broadcast but parts from different sources")
            }
        } else {
            source.replace(src_key.id().clone());
        } 
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

        if let Some(ret) = decoder.decode(bcast.seqno as u32, &bcast.data) {
            if ret.len() != bcast.data_size as usize {
                fail!("Expected {} bytes, but received {}", bcast.data_size, ret.len())
            } else {
                log::trace!(target: TARGET, "Received overlay broadcast, {} bytes", ret.len()) 
            }
            if let Some(source) = source.take() {
                Ok(Some((ret, source)))
            } else {
                fail!("Broadcast without source")
            }
        } else {
            Ok(None)
        }

    }

    async fn receive_broadcast(
        overlay_shard: &Arc<Self>, 
        bcast: Box<BroadcastOrd>,
        raw_data: &[u8],
        local_key: &Arc<KeyId> 
    ) -> Result<()> {           
        let src_key = KeyOption::from_tl_public_key(&bcast.src)?;
        let src = if (bcast.flags & Self::FLAG_BCAST_ANY_SENDER) != 0 {
            [0u8; 32]
        } else {                           
            src_key.id().data().clone()
        };
        let signature = Self::calc_broadcast_to_sign(&bcast.data, bcast.date, src)?;
        let bcast_id = if let Some(bcast_id) = overlay_shard.calc_broadcast_id(&signature)? {
            bcast_id
        } else {
            return Ok(());
        };
        src_key.verify(&signature, &bcast.signature.0)?;
        let ton::bytes(data) = bcast.data;
        log::trace!(target: TARGET, "Received overlay broadcast, {} bytes", data.len());
        BroadcastReceiver::push(&overlay_shard.received_rawbytes, (data, src_key.id().clone()));
        overlay_shard.distribute_broadcast(raw_data, local_key).await?;
        overlay_shard.purge_count.fetch_add(1, Ordering::Relaxed);
        overlay_shard.purge_broadcasts.push(bcast_id);
        Ok(())
     }

    async fn receive_fec_broadcast(
        overlay_shard: &Arc<Self>, 
        bcast: Box<BroadcastFec>,
        raw_data: &[u8],
        local_key: &Arc<KeyId> 
    ) -> Result<()> {
        let bcast_id = get256(&bcast.data_hash);
        let transfer = if let Some(transfer) = overlay_shard.transfers_fec.get(bcast_id) {
            transfer
        } else {
            let added = add_object_to_map(
                &overlay_shard.past_broadcasts,
                bcast_id.clone(),
                || Ok(())
            )?;
            if !added {
                return Ok(())
            }
            add_object_to_map(
                &overlay_shard.transfers_fec,
                bcast_id.clone(),
                || Self::create_fec_recv_transfer(overlay_shard, &bcast)
            )?;
            if let Some(transfer) = overlay_shard.transfers_fec.get(bcast_id) {
                transfer
            } else {
                return Ok(())
            }
        };
        let transfer = transfer.val();
        if !transfer.completed.load(Ordering::Relaxed) {
            transfer.sender.send(bcast)?;
            transfer.updated_at.refresh();
            overlay_shard.distribute_broadcast(raw_data, local_key).await?;
        }
        Ok(())
    }

    async fn send_broadcast(&self, data: &[u8], key: &Arc<KeyOption>) -> Result<()> {    
        let date = Version::get();
        let signature = Self::calc_broadcast_to_sign(data, date, [0u8; 32])?;
/*        
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
*/
        let signature = key.sign(&signature)?;
        let bcast = BroadcastOrd {
            src: key.into_tl_public_key()?,
            certificate: OverlayCertificate::Overlay_EmptyCertificate,
            flags: Self::FLAG_BCAST_ANY_SENDER,
            data: ton::bytes(data.to_vec()),
            date: Version::get(),
            signature: ton::bytes(signature.to_vec())
        }.into_boxed();                                   
        let mut buf = self.message_prefix.clone();
        serialize_append(&mut buf, &bcast)?;
        self.distribute_broadcast(&buf, key.id()).await
    } 

    fn update_neighbours(&self, n: u32) -> Result<()> {
        self.random_peers.random_set(&self.neighbours, n)
    }

}

struct RecvTransferFec {
    completed: AtomicBool,
    sender: tokio::sync::mpsc::UnboundedSender<Box<BroadcastFec>>,
    updated_at: UpdatedAt
}

struct SendTransferFec {
    bcast_id: BroadcastId,
    encoder: RaptorqEncoder,
    seqno: u32
}

#[async_trait::async_trait]
pub trait QueriesConsumer: Send + Sync {
    async fn try_consume_query(&self, query: TLObject) -> Result<QueryResult>;
}

/// Overlay Node
pub struct OverlayNode {
    adnl: Arc<AdnlNode>,
    node_key: Arc<KeyOption>, 
    shards: lockfree::map::Map<Arc<OverlayShortId>, Arc<OverlayShard>>,
    consumers: lockfree::map::Map<Arc<OverlayShortId>, Arc<dyn QueriesConsumer>>,
    zero_state_file_hash: [u8; 32]
}

impl OverlayNode {

    const MAX_BROADCAST_LOG: u32 = 1000;
    const MAX_PEERS: u32 = 65536;
    const MAX_RANDOM_PEERS: u32 = 4;
    const MAX_SHARD_NEIGHBOURS: u32 = 5;
    const MAX_SHARD_PEERS: u32 = 20;
    const MAX_SIZE_ORDINARY_BROADCAST: usize = 768;
    const TIMEOUT_GC: u64 = 1000; // Milliseconds

    /// Constructor 
    pub fn with_adnl_node_and_zero_state(
        adnl: Arc<AdnlNode>, 
        zero_state_file_hash: &[u8; 32],
        key_tag: usize
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        let ret = Self { 
            adnl,
            node_key,
            shards: lockfree::map::Map::new(),
            consumers: lockfree::map::Map::new(),
            zero_state_file_hash: zero_state_file_hash.clone()
        };
        Ok(Arc::new(ret))
    }

    /// Add overlay query consumer
    pub fn add_consumer(&self, overlay_id: &Arc<OverlayShortId>, consumer: Arc<dyn QueriesConsumer>) -> Result<bool> {
        log::debug!(target: TARGET, "Add consumer {} to overlay", overlay_id);
        add_object_to_map(
            &self.consumers,
            overlay_id.clone(),
            || Ok(consumer.clone())
        )
    }

    /// Add private_overlay
    pub async fn add_private_overlay(
        &self, 
        overlay_id: &Arc<OverlayShortId>,
        local_key: &Arc<KeyId>, 
        peers: &Vec<Arc<KeyId>>
    ) -> Result<bool> {
        if self.add_overlay(overlay_id, Some(local_key.clone())).await? {
            let shard = self.shards.get(overlay_id).ok_or_else(
                || error!("Cannot add the private overlay {}", overlay_id)
            )?;
            let shard = shard.val(); 
            for peer in peers {
                shard.known_peers.put(peer.clone())?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Add private overlay peers 
    pub fn add_private_peers(
        &self, 
        local_key: &Arc<KeyId>, 
        peers: Vec<(IpAddress, KeyOption)>
    ) -> Result<Vec<Arc<KeyId>>> {
        let mut ret = Vec::new();
        for (ip, key) in peers {
            if let Some(peer) = self.adnl.add_peer(local_key, &ip, &Arc::new(key))? {
                ret.push(peer)
            }
        }
        Ok(ret)
    }

    /// Add public overlay peer 
    pub fn add_public_peer(
        &self, 
        peer_ip_address: &IpAddress, 
        peer: &Node,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<Arc<KeyId>>> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Trying add peer to unknown public overlay {}", overlay_id)
        )?;
        let shard = shard.val(); 
        if shard.overlay_key.is_some() {
            fail!("Trying to add public peer to private overlay {}", overlay_id)
        }
        if let Err(e) = OverlayUtils::verify_node(overlay_id, peer) {
            log::warn!(target: TARGET, "Error when verifying Overlay peer: {}", e);
            return Ok(None)
        }
        let ret = self.adnl.add_peer(
            self.node_key.id(), 
            peer_ip_address, 
            &Arc::new(KeyOption::from_tl_public_key(&peer.id)?)
        )?;
        let ret = if let Some(ret) = ret {
            ret
        } else {
            return Ok(None)
        };
        shard.known_peers.put(ret.clone())?;
        if shard.random_peers.count() < Self::MAX_SHARD_PEERS {
            shard.random_peers.put(ret.clone())?;
        }            
        if shard.neighbours.count() < Self::MAX_SHARD_NEIGHBOURS {
            shard.update_neighbours(Self::MAX_SHARD_NEIGHBOURS)?;
        }          
        add_object_to_map_with_update(
            &shard.nodes,
            ret.clone(),
            |old_node| if let Some(old_node) = old_node {
                if old_node.version < peer.version {
                    Ok(Some(peer.clone()))
                } else {
                    Ok(None)
                }
            } else {
                Ok(Some(peer.clone()))
            }
        )?;
        Ok(Some(ret))
    }

    /// Add shard
    pub async fn add_shard(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        self.add_overlay(overlay_id, None).await
    }

    /// Broadcast message 
    pub async fn broadcast(&self, overlay_id: &Arc<OverlayShortId>, data: &[u8]) -> Result<u32> {
        log::trace!(target: TARGET, "Broadcast {} bytes", data.len());
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Trying broadcast to unknown overlay {}", overlay_id)
        )?;
        if data.len() <= Self::MAX_SIZE_ORDINARY_BROADCAST {
            shard.val().send_broadcast(data, &self.node_key).await?
        } else {
            OverlayShard::create_fec_send_transfer(shard.val(), data, &self.node_key)?
        }
        Ok(shard.val().neighbours.count())
    } 

    /// Calculate overlay ID for shard
    pub fn calc_overlay_id(
        &self, 
        workchain: i32, 
        shard: i64 
    ) -> Result<OverlayId> {
        OverlayUtils::calc_overlay_id(workchain, shard, &self.zero_state_file_hash)
    }

    /// Calculate overlay short ID for shard
    pub fn calc_overlay_short_id(
        &self, 
        workchain: i32, 
        shard: i64 
    ) -> Result<Arc<OverlayShortId>> {
        OverlayUtils::calc_overlay_short_id(workchain, shard, &self.zero_state_file_hash)
    }

    /// Delete private_overlay
    pub fn delete_private_overlay(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        if let Some(shard) = self.shards.get(overlay_id) {
            shard.val().overlay_key.as_ref().ok_or_else(
                || error!("Try to delete public overlay {}", overlay_id)
            )?; 
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete private overlay peers 
    pub fn delete_private_peers(
        &self, 
        local_key: &Arc<KeyId>, 
        peers: &Vec<Arc<KeyId>>
    ) -> Result<bool> {
        let mut ret = false;
        for peer in peers {               
            ret = self.adnl.delete_peer(local_key, peer)? || ret
        }    
        Ok(ret)
    }

    /// Get query prefix
    pub fn get_query_prefix(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Vec<u8>> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Getting query prefix of unknown overlay {}", overlay_id)
        )?;
        Ok(shard.val().query_prefix.clone())
    }
    
    /// overlay.GetRandomPeers
    pub async fn get_random_peers(
        &self, 
        dst: &Arc<KeyId>, 
        overlay_id: &Arc<OverlayShortId>,
        timeout: Option<u64>
    ) -> Result<Option<Vec<Node>>> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Getting random peers from unknown overlay {}", overlay_id)
        )?;
        log::trace!(target: TARGET, "Get random peers from {}", dst);
        let peers = GetRandomPeers {
            peers: self.prepare_random_peers(shard.val())?
        };
        let query = TLObject::new(peers);
        let answer = self.query(dst, &query, overlay_id, timeout).await?;
        if let Some(answer) = answer {
            let answer: NodesBoxed = Query::parse(answer, &query)?;
            log::trace!(target: TARGET, "Got random peers from {}", dst);
            Ok(Some(Self::process_random_peers(overlay_id, answer.only())?))
        } else {
            log::warn!(target: TARGET, "No random peers from {}", dst);
            Ok(None)    
        }
    }

    /// Get signed node
    pub fn get_signed_node(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Node> {
        self.sign_local_node(overlay_id)
    }

    /// Send message via ADNL
    pub async fn message(
        &self, 
        dst: &Arc<KeyId>, 
        data: &[u8],
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<()> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Sending message to unknown overlay {}", overlay_id)
        )?;
        let peers = AdnlPeers::with_keys(self.node_key.id().clone(), dst.clone());
        let mut buf = shard.val().message_prefix.clone();
        buf.extend_from_slice(data);
        self.adnl.send_custom(&buf, &peers).await
    }

    /// Send query via ADNL
    pub async fn query(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TLObject,
        overlay_id: &Arc<OverlayShortId>,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Sending query to unknown overlay {}", overlay_id)
        )?;
        let peers = AdnlPeers::with_keys(self.node_key.id().clone(), dst.clone());
        self.adnl.query_with_prefix(
            Some(&shard.val().query_prefix), 
            query,
            &peers,
            timeout
        ).await
    }

    /// Send query via RLDP
    pub async fn query_via_rldp(
        &self, 
        rldp: &Arc<RldpNode>,
        dst: &Arc<KeyId>, 
        data: &[u8],
        max_answer_size: Option<i64>,
        roundtrip_adnl: Option<u64>,
        roundtrip_rldp: Option<u64>
    ) -> Result<Option<Vec<u8>>> {
        let peers = AdnlPeers::with_keys(self.node_key.id().clone(), dst.clone());
        rldp.query(data, max_answer_size, &peers, roundtrip_adnl, roundtrip_rldp).await
    }

    /// Wait for broadcast
    pub async fn wait_for_broadcast(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<(Vec<u8>, Arc<KeyId>)> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Waiting for broadcast in unknown overlay {}", overlay_id)
        )?;
        shard.val().received_rawbytes.pop().await
    }

    /// Wait for catchain
    pub async fn wait_for_catchain(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<(CatchainBlockUpdate, ValidatorSessionBlockUpdate, Arc<KeyId>)> {
        let shard = self.shards.get(overlay_id).ok_or_else(
            || error!("Waiting for catchain in unknown overlay {}", overlay_id)
        )?;
        shard.val().received_catchain.as_ref().ok_or_else(
            || error!("Waiting for catchain in public overlay {}", overlay_id)
        )?.pop().await
    }

    async fn add_overlay(
        &self, 
        overlay_id: &Arc<OverlayShortId>, 
        overlay_key: Option<Arc<KeyId>>
    ) -> Result<bool> {
        log::debug!(target: TARGET, "Add overlay {} to node", overlay_id);
        let added = add_object_to_map(
            &self.shards,
            overlay_id.clone(), 
            || {
                let message_prefix = OverlayMessage {
                    overlay: ton::int256(overlay_id.data().clone())
                }.into_boxed();
                let query_prefix = OverlayQuery {
                    overlay: ton::int256(overlay_id.data().clone())
                };
                let received_catchain = if overlay_key.is_some() {
                    let received_catchain = Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0)
                        }
                    );
                    Some(received_catchain)
                } else {
                    None
                };
                let shard = OverlayShard {
                    adnl: self.adnl.clone(),
                    message_prefix: serialize(&message_prefix)?,
                    known_peers: AddressCache::with_limit(Self::MAX_PEERS),
                    neighbours: AddressCache::with_limit(Self::MAX_SHARD_NEIGHBOURS), 
                    nodes: lockfree::map::Map::new(),
                    overlay_id: overlay_id.clone(),
                    overlay_key: overlay_key.clone(),
                    past_broadcasts: lockfree::map::Map::new(),
                    purge_broadcasts: lockfree::queue::Queue::new(),
                    purge_count: AtomicU32::new(0),
                    query_prefix: serialize(&query_prefix)?,
                    random_peers: AddressCache::with_limit(Self::MAX_SHARD_PEERS),
                    received_catchain,
                    received_rawbytes: Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0)
                        }
                    ),
                    transfers_fec: lockfree::map::Map::new()
                };
                shard.update_neighbours(Self::MAX_SHARD_NEIGHBOURS)?;
                Ok(Arc::new(shard))
            }
        )?;
        if added {
            let shard = self.shards.get(overlay_id).ok_or_else(
                || error!("Cannot add overlay {}", overlay_id)
            )?;
            let shard = shard.val().clone();
            tokio::spawn(
                async move {
                    while Arc::strong_count(&shard) > 1 {
                        while shard.purge_count.load(Ordering::Relaxed) > Self::MAX_BROADCAST_LOG {
                            if let Some(bcast_id) = shard.purge_broadcasts.pop() {
                                shard.past_broadcasts.remove(&bcast_id);
                            }
                            shard.purge_count.fetch_sub(1, Ordering::Relaxed);
                        }
                        tokio::time::delay_for(Duration::from_millis(Self::TIMEOUT_GC)).await;
                    }
                }
            );
        }
        Ok(added)
    }

    fn prepare_random_peers(&self, shard: &OverlayShard) -> Result<Nodes> {
        let mut ret = vec![self.sign_local_node(&shard.overlay_id)?];
        let nodes = AddressCache::with_limit(Self::MAX_RANDOM_PEERS);
        shard.random_peers.random_set(&nodes, Self::MAX_RANDOM_PEERS)?;
        let (mut iter, mut current) = nodes.first();
        while let Some(node) = current {
            if let Some(node) = shard.nodes.get(&node) {
                ret.push(node.val().clone())
            }
            current = nodes.next(&mut iter)
        }
        let ret = Nodes {
            nodes: ret.into()
        };
        Ok(ret)
    }

    fn process_random_peers(overlay_id: &Arc<OverlayShortId>, peers: Nodes) -> Result<Vec<Node>> {
        let mut ret = Vec::new();
        log::trace!(target: TARGET, "-------- Got random peers:");
        let mut peers = peers.nodes.0;
        while let Some(peer) = peers.pop() {
            log::trace!(target: TARGET, "{:?}", peer);
            if let Err(e) = OverlayUtils::verify_node(overlay_id, &peer) {
                log::warn!(target: TARGET, "Error when verifying Overlay peer: {}", e);
                continue
            }
            ret.push(peer)
        }
        Ok(ret)
    }

    fn process_get_random_peers(
        &self, 
        shard: &OverlayShard, 
        query: GetRandomPeers
    ) -> Result<Nodes> {
        log::trace!(target: TARGET, "Got random peers request");
        Self::process_random_peers(&shard.overlay_id, query.peers)?;
        self.prepare_random_peers(shard)
    }

    fn sign_local_node(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Node> {
        let version = Version::get();
        let local_node = NodeToSign {
            id: AdnlShortId {
                id: ton::int256(self.node_key.id().data().clone())
            },
            overlay: ton::int256(overlay_id.data().clone()),
            version 
        }.into_boxed();     
        let local_node = Node {
            id: self.node_key.into_tl_public_key()?,
            overlay: ton::int256(overlay_id.data().clone()),
            signature: ton::bytes(self.node_key.sign(&serialize(&local_node)?)?.to_vec()),
            version
        };     
        Ok(local_node)
    }

}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {
                                                           
    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let mut bundle = deserialize_bundle(data)?;
        if (bundle.len() < 2) || (bundle.len() > 3) {
            return Ok(false)
        }
        let overlay_id = match bundle.remove(0).downcast::<OverlayMessageBoxed>() {
            Ok(msg) => {
                let OverlayMessage { 
                    overlay: ton::int256(overlay_id)
                } = msg.only();
                OverlayShortId::from_data(overlay_id)
            },
            Err(msg) => {
                log::debug!(target: TARGET, "Unsupported overlay message {:?}", msg);
                return Ok(false)
            }
        };
        let overlay_shard = if let Some(overlay_shard) = self.shards.get(&overlay_id) {                                                      
            overlay_shard
        } else {
            fail!("Message to unknown overlay {}", overlay_id)
        };
        if bundle.len() == 2 {
            // Private overlay
            let catchain_update = match bundle.remove(0).downcast::<CatchainBlockUpdateBoxed>() {
                Ok(CatchainBlockUpdateBoxed::Catchain_BlockUpdate(upd)) => *upd,
                Err(msg) => fail!("Unsupported private overlay message {:?}", msg)
            };
            let validator_session_update = 
                match bundle.remove(0).downcast::<ValidatorSessionBlockUpdateBoxed>() {
                    Ok(ValidatorSessionBlockUpdateBoxed::ValidatorSession_BlockUpdate(upd)) => *upd,
                    Err(msg) => fail!("Unsupported private overlay message {:?}", msg)
                };
            let receiver = overlay_shard.val().received_catchain.as_ref().ok_or_else(
                || error!("No catchain receiver in private overlay {}", overlay_id)
            )?;
            BroadcastReceiver::push(
                receiver, 
                (catchain_update, validator_session_update, peers.other().clone())
            );
            Ok(true)
        } else {
            // Public overlay
            match bundle.remove(0).downcast::<Broadcast>() {
                Ok(Broadcast::Overlay_BroadcastFec(bcast)) => {
                    OverlayShard::receive_fec_broadcast(
                        overlay_shard.val(), bcast, data, peers.local()
                    ).await?;
                    Ok(true)
                },
                Ok(Broadcast::Overlay_Broadcast(bcast)) => {
                    OverlayShard::receive_broadcast(
                        overlay_shard.val(), bcast, data, peers.local()
                    ).await?;
                    Ok(true)
                },
                Ok(bcast) => fail!("Unsupported overlay broadcast message {:?}", bcast),
                Err(msg) => fail!("Unsupported overlay message {:?}", msg)
            }
        }
    }

    async fn try_consume_query(&self, object: TLObject) -> Result<QueryResult> {
        log::error!(target: TARGET, "try_consume_query OVERLAY {:?}", object);
        Ok(QueryResult::Rejected(object))                                    
    }    

    async fn try_consume_query_bundle(&self, mut objects: Vec<TLObject>) -> Result<QueryResult> {    
        if objects.len() != 2 {
            return Ok(QueryResult::RejectedBundle(objects))
        }
        let overlay_id = match objects.remove(0).downcast::<OverlayQuery>() {
            Ok(query) => {
                let ton::int256(overlay_id) = query.overlay;
                OverlayShortId::from_data(overlay_id)
            },
            Err(query) => {
                objects.insert(0, query);
                return Ok(QueryResult::RejectedBundle(objects))
            }
        };                                
        let object = match objects.remove(0).downcast::<GetRandomPeers>() {
            Ok(query) => {                
                let overlay_shard = if let Some(overlay_shard) = self.shards.get(&overlay_id) {                                                      
                    overlay_shard
                } else {
                    fail!("Query to unknown overlay {}", overlay_id)
                };
                return QueryResult::consume(
                    self.process_get_random_peers(overlay_shard.val(), query)?
                );
            }
            Err(object) => object
        };
        let consumer = if let Some(consumer) = self.consumers.get(&overlay_id) {
            consumer
        } else {
            fail!("No consumer for message in overlay {}", overlay_id)
        };
        match consumer.val().try_consume_query(object).await {
            Err(msg) => fail!("Unsupported query, overlay: {}, query: {}", overlay_id, msg),
            r => r
        }
    }

}
