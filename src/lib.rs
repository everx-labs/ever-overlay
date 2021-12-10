/*
* Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

use adnl::{
    declare_counted,
    common::{
        add_counted_object_to_map, add_counted_object_to_map_with_update, 
        add_unbound_object_to_map, AdnlPeers, CountedObject, Counter, deserialize_bundle, 
        get256, hash, hash_boxed, KeyId, KeyOption, Query, QueryResult, serialize, 
        serialize_append, Subscriber, TaggedByteSlice, TaggedTlObject, UpdatedAt, Version
    }, 
    node::{AddressCache, AdnlNode, IpAddress, PeerHistory}
};
#[cfg(feature = "telemetry")]
use adnl::{common::{tag_from_boxed_type, tag_from_unboxed_type}, telemetry::Metric};
#[cfg(feature = "compression")]
use adnl::node::DataCompression;
use rldp::{RaptorqDecoder, RaptorqEncoder, RldpNode};
use sha2::Digest;
use std::{
    convert::TryInto, sync::{Arc, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}},
    time::Duration
};
#[cfg(feature = "telemetry")]
use std::time::Instant;
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
#[cfg(feature = "telemetry")]
use ton_api::BoxedSerialize;
use ton_types::{error, fail, Result};

const TARGET: &str = "overlay";
const TARGET_BROADCAST: &str = "overlay_broadcast";

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
    let key: [u8; 32] = key.as_slice().try_into()?;
    let signature = base64::decode(signature)?;
    let node = Node {
        id: Ed25519 {
            key: ton::int256(key)
        }.into_boxed(),
        overlay: ton::int256(*overlay.data()),
        version,
        signature: ton::bytes(signature)
    };
    Ok(node)
}

struct BroadcastReceiver<T> {
    data: lockfree::queue::Queue<Option<T>>,
    subscribers: lockfree::queue::Queue<Arc<tokio::sync::Barrier>>,
    synclock: AtomicU32,
}

impl <T: Send + 'static> BroadcastReceiver<T> {

    fn push(receiver: &Arc<Self>, data: T) {
        Self::do_push(receiver, Some(data))
    }

    async fn pop(&self) -> Result<Option<T>> {
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

    fn stop(receiver: &Arc<Self>) {
        Self::do_push(receiver, None)
    }

    fn do_push(receiver: &Arc<Self>, data: Option<T>) {
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

}

pub struct BroadcastRecvInfo {
    pub packets: u32,
    pub data: Vec<u8>,
    pub recv_from: Arc<KeyId>
}

#[derive(Debug, Default)]
pub struct BroadcastSendInfo {
    pub packets: u32,
    pub send_to: u32
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
            zero_state_file_hash: ton::int256(*zero_state_file_hash)
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
                id: ton::int256(*key.id().data())
            },
            overlay: node.overlay,
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

enum OwnedBroadcast {
    Other,
    RecvFec(RecvTransferFec),
    WillBeRecvFec
}

#[cfg(feature = "telemetry")]
declare_counted!(
    struct TransferStats {
        income: AtomicU64,
        passed: AtomicU64,
        resent: AtomicU64
    }
);

#[cfg(feature = "telemetry")]
declare_counted!(
    struct PeerStats {
        count: AtomicU64
    }
);

declare_counted!(
    struct NodeObject {
        object: Node
    }
);

declare_counted!(
    struct OverlayShard {
        adnl: Arc<AdnlNode>,
        bad_peers: lockfree::set::Set<Arc<KeyId>>,
        known_peers: AddressCache,
        message_prefix: Vec<u8>,
        neighbours: AddressCache,
        nodes: lockfree::map::Map<Arc<KeyId>, NodeObject>,
        options: Arc<AtomicU32>,
        overlay_id: Arc<OverlayShortId>,
        overlay_key: Option<Arc<KeyOption>>,
        owned_broadcasts: lockfree::map::Map<BroadcastId, OwnedBroadcast>,
        purge_broadcasts: lockfree::queue::Queue<BroadcastId>,
        purge_broadcasts_count: AtomicU32,
        query_prefix: Vec<u8>,
        random_peers: AddressCache,
        received_catchain: Option<Arc<CatchainReceiver>>,
        received_peers: Arc<BroadcastReceiver<Vec<Node>>>,
        received_rawbytes: Arc<BroadcastReceiver<BroadcastRecvInfo>>,
        #[cfg(feature = "telemetry")]
        start: Instant,
        #[cfg(feature = "telemetry")]
        print: AtomicU64,
        #[cfg(feature = "telemetry")]
        messages_recv: AtomicU64,
        #[cfg(feature = "telemetry")]
        messages_send: AtomicU64,
        #[cfg(feature = "telemetry")]
        stats_per_peer_recv: lockfree::map::Map<Arc<KeyId>, lockfree::map::Map<u32, PeerStats>>,
        #[cfg(feature = "telemetry")]
        stats_per_peer_send: lockfree::map::Map<Arc<KeyId>, lockfree::map::Map<u32, PeerStats>>,
        #[cfg(feature = "telemetry")]
        stats_per_transfer: lockfree::map::Map<BroadcastId, TransferStats>,
        #[cfg(feature = "telemetry")]
        tag_broadcast_fec: u32,
        #[cfg(feature = "telemetry")]
        tag_broadcast_ord: u32,
        #[cfg(feature = "telemetry")]
        telemetry: Arc<OverlayTelemetry>,
        allocated: Arc<OverlayAlloc>,
        // For debug
        debug_trace: AtomicU32
   }
);

impl OverlayShard {

    const FLAG_BCAST_ANY_SENDER: i32 = 0x01;
    const OPTION_DISABLE_BROADCAST_RETRANSMIT: u32 = 0x01;
    const SIZE_BROADCAST_WAVE: u32 = 20;
    const SPINNER: u64 = 10;              // Milliseconds
    const TIMEOUT_BROADCAST: u64 = 60;    // Seconds

    fn calc_broadcast_id(&self, data: &[u8]) -> Result<Option<BroadcastId>> {
        let bcast_id: [u8; 32] = sha2::Sha256::digest(data).try_into()?;
        let added = add_unbound_object_to_map(
            &self.owned_broadcasts,
            bcast_id,
            || Ok(OwnedBroadcast::Other)
        )?;
        if !added {
            Ok(None)
        } else {
            Ok(Some(bcast_id))
        }
    }

    fn calc_broadcast_to_sign(data: &[u8], date: i32, src: [u8; 32]) -> Result<Vec<u8>> { 
        let data_hash: [u8; 32] = sha2::Sha256::digest(data).try_into()?;
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

    #[allow(clippy::too_many_arguments)]
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
            data_hash: ton::int256(*data_hash),
            size: data_size,
            flags
        };
        let broadcast_hash = hash(broadcast_id)?;
        let part_data_hash: [u8; 32] = sha2::Sha256::digest(part).try_into()?;

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
        bcast: &BroadcastFec
    ) -> Result<RecvTransferFec> {

        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type
        } else {
            fail!("Unsupported FEC type")
        };
                        
        let overlay_shard_recv = overlay_shard.clone();
        let bcast_id_recv = *get256(&bcast.data_hash);
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
        let mut decoder = RaptorqDecoder::with_params(fec_type.clone());
        let overlay_shard_wait = overlay_shard_recv.clone();
        let bcast_id_wait = bcast_id_recv;
        let source = KeyOption::from_tl_public_key(&bcast.src)?.id().clone();
        let source_recv = source.clone();
        let bcast_data_size = bcast.data_size;
                
        tokio::spawn(
            async move {
                let mut received = false;
                let mut packets = 0;
                #[cfg(feature = "telemetry")]
                let mut flags = RecvTransferFecTelemetry::FLAG_RECEIVE_STARTED;
                #[cfg(feature = "telemetry")]
                let mut len = 0;
                #[cfg(feature = "telemetry")]
                let mut tag = 0;
                while let Some(bcast) = reader.recv().await {
                    let bcast = match bcast {
                        Some(bcast) => bcast,
                        None => break
                    };
                    packets += 1; 
                    match Self::process_fec_broadcast(&mut decoder, &bcast) {
                        Err(err) => {
                            log::warn!(  
                                target: TARGET, 
                                "Error when receiving overlay {} broadcast: {}",
                                overlay_shard_recv.overlay_id,
                                err
                            );
                            #[cfg(feature = "telemetry")] {
                                flags |= RecvTransferFecTelemetry::FLAG_FAILED;
                            }
                        },
                        Ok(Some(data)) => {
                            #[cfg(feature = "telemetry")] {
                                if data.len() > 4 {
                                    tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                                }
                                len = data.len() as u32;
                                flags |= RecvTransferFecTelemetry::FLAG_RECEIVED;
                            }
                            BroadcastReceiver::push(
                                &overlay_shard_recv.received_rawbytes, 
                                BroadcastRecvInfo {
                                    packets, 
                                    data, 
                                    recv_from: source_recv
                                }
                            );
                            received = true
                        },
                        Ok(None) => continue
                    } 
                    break;
                }   
                if received {
                    if let Some(transfer) = overlay_shard_recv.owned_broadcasts.get(
                        &bcast_id_recv
                    ) {
                        if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                            transfer.completed.store(true, Ordering::Relaxed);
                            #[cfg(feature = "telemetry")] {
                                transfer.telemetry.flags.fetch_or(flags, Ordering::Relaxed);
                                transfer.telemetry.len.store(len, Ordering::Relaxed);
                                transfer.telemetry.tag.store(tag, Ordering::Relaxed);
                            }
                        } else {
                            log::error!(  
                                target: TARGET, 
                                "INTERNAL ERROR: recv FEC broadcast {} mismatch in overlay {}",
                                base64::encode(&bcast_id_recv),
                                overlay_shard_recv.overlay_id
                            )
                        }
                    }
                }
                // Graceful close
                reader.close();
                while reader.recv().await.is_some() { 
                }
            }
        );

        tokio::spawn(
            async move {
                loop {
                    tokio::time::sleep(
                        Duration::from_millis(Self::TIMEOUT_BROADCAST * 100)
                    ).await;
                    if let Some(transfer) = overlay_shard_wait.owned_broadcasts.get(
                        &bcast_id_wait
                    ) {
                        if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                            if !transfer.updated_at.is_expired(Self::TIMEOUT_BROADCAST) {
                                continue
                            }
                            if !transfer.completed.load(Ordering::Relaxed) {
                                log::warn!(  
                                    target: TARGET, 
                                    "FEC broadcast {} ({} bytes) dropped incompleted by timeout",
                                    base64::encode(&bcast_id_wait),
                                    bcast_data_size
                                )
                            }
                            // Abort receiving loop
                            transfer.sender.send(None).ok();
                        } else {
                            log::error!(  
                                target: TARGET, 
                                "INTERNAL ERROR: recv FEC broadcast {} mismatch in overlay {}",
                                base64::encode(&bcast_id_wait),
                                overlay_shard_wait.overlay_id
                            )
                        }
                    }
                    break
                }
                Self::setup_broadcast_purge(&overlay_shard_wait, bcast_id_wait);
            }
        );

        let ret = RecvTransferFec {
            completed: AtomicBool::new(false),
            history: PeerHistory::for_recv(),
            sender,
            source,
            #[cfg(feature = "telemetry")]
            telemetry: RecvTransferFecTelemetry {
                flags: AtomicU32::new(0),
                len: AtomicU32::new(0),
                tag: AtomicU32::new(0)
            },
            updated_at: UpdatedAt::new(),
            counter: overlay_shard.allocated.recv_transfers.clone().into()
        };
        #[cfg(feature = "telemetry")]
        overlay_shard.telemetry.recv_transfers.update(
            overlay_shard.allocated.recv_transfers.load(Ordering::Relaxed)
        );  
        Ok(ret)

    }

    fn create_fec_send_transfer(
        overlay_shard: &Arc<Self>, 
        data: &TaggedByteSlice, 
        source: &Arc<KeyOption>,
        overlay_key: &Arc<KeyId>
    ) -> Result<BroadcastSendInfo> {

        let overlay_shard_clone = overlay_shard.clone();
        let source = source.clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();

        let bcast_id = if let Some(bcast_id) = overlay_shard.calc_broadcast_id(data.object)? {
            bcast_id
        } else {
            log::warn!(target: TARGET, "Trying to send duplicated broadcast");
            return Ok(BroadcastSendInfo::default())
        };

        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        #[cfg(feature = "compression")]
        let data = &DataCompression::compress(data.object)?[..];
        #[cfg(not(feature = "compression"))]
        let data = data.object;
        let data_size = data.len() as u32;

        let mut transfer = SendTransferFec {
            bcast_id,
            encoder: RaptorqEncoder::with_data(data),
            seqno: 0,
            counter: overlay_shard.allocated.send_transfers.clone().into()
        };
        #[cfg(feature = "telemetry")]
        overlay_shard.telemetry.send_transfers.update(
            overlay_shard.allocated.send_transfers.load(Ordering::Relaxed)
        );       
        let max_seqno = (data_size / transfer.encoder.params().symbol_size as u32 + 1) * 3 / 2;
        
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: send FEC {} {} bytes, tag {:08x} to overlay {}",
            base64::encode(&bcast_id),  
            data.len(),
            tag,
            overlay_shard.overlay_id
        );

        tokio::spawn(
            async move {
                while transfer.seqno <= max_seqno {
                    for _ in 0..Self::SIZE_BROADCAST_WAVE {
                        let result = overlay_shard_clone
                            .prepare_fec_broadcast(&mut transfer, &source)
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
                            return
                        }
                        if transfer.seqno > max_seqno {
                            break
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(Self::SPINNER)).await;            
                }   
            }
        );

        let overlay_shard = overlay_shard.clone();
        let overlay_key = overlay_key.clone();
        let neighbours = overlay_shard.neighbours.random_vec(None, 5);
        let ret = BroadcastSendInfo {
            packets: max_seqno,
            send_to: neighbours.len() as u32
        };     
        
        tokio::spawn(
            async move {
                while let Some(buf) = reader.recv().await {
                    if let Err(err) = overlay_shard.distribute_broadcast(
                        &TaggedByteSlice {
                            object: &buf, 
                            #[cfg(feature = "telemetry")]
                            tag
                        },
                        &overlay_key,
                        &neighbours, 
                    ).await {
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
                while reader.recv().await.is_some() { 
                }
                Self::setup_broadcast_purge(&overlay_shard, bcast_id);
            }
        );
        Ok(ret)
        
    }

    async fn distribute_broadcast(
        &self, 
        data: &TaggedByteSlice<'_>,
        key: &Arc<KeyId>,
        neighbours: &[Arc<KeyId>]
    ) -> Result<()> {   
        log::trace!(
            target: TARGET,
            "Broadcast {} bytes to overlay {}, {} neighbours",
            data.object.len(),
            self.overlay_id, 
            neighbours.len()
        );
        let mut peers: Option<AdnlPeers> = None;
        #[cfg(feature = "telemetry")]
        let mut addrs = Vec::new();
        for neighbour in neighbours.iter() {
            #[cfg(feature = "telemetry")]
            if let Err(e) = self.update_stats(neighbour, data.tag, true) {
                log::warn!(
                    target: TARGET,
                    "Cannot update statistics in overlay {} for {} during broadcast: {}",
                    self.overlay_id, neighbour, e
                )
            }
            let peers = if let Some(peers) = &mut peers {
                peers.set_other(neighbour.clone());
                peers
            } else {
                peers.get_or_insert_with(|| AdnlPeers::with_keys(key.clone(), neighbour.clone()))
            };
            #[cfg(feature = "telemetry")]
            addrs.push(format!("{}", peers.other()));
            if let Err(e) = self.adnl.send_custom(data, peers.clone()) {
                log::warn!(
                    target: TARGET,
                    "Cannot distribute broadcast in overlay {} to {}: {}",
                    self.overlay_id, neighbour, e
                )
            }
        }
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: distributed {} bytes to overlay {}, peers {:?}",
            data.object.len(),
            self.overlay_id,
            addrs
        );
        Ok(())
    }

    fn is_broadcast_outdated(&self, date: i32, peer: &Arc<KeyId>) -> bool {
        let now = Version::get();
        if date + (Self::TIMEOUT_BROADCAST as i32) < now {
            log::warn!(
                target: TARGET,
                "Old FEC broadcast {} seconds old from {} in overlay {}",
                now - date, 
                peer, 
                self.overlay_id
            );
            true
        } else {
            false
        }
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
            data_hash: ton::int256(transfer.bcast_id),
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
        bcast: &BroadcastFec
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
            *src_key.id().data()
        };

        let bcast_id = get256(&bcast.data_hash);
        let signature = Self::calc_fec_part_to_sign(
            bcast_id,
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
            let ret = if ret.len() != bcast.data_size as usize {
                fail!("Expected {} bytes, but received {}", bcast.data_size, ret.len())
            } else {
                #[cfg(feature = "compression")]
                let ret = DataCompression::decompress(&ret[..])?;
                let test_id = sha2::Sha256::digest(&ret);
                if test_id.as_slice() != bcast_id {
                    fail!(
                        "Expected {} broadcast hash, but received {}", 
                        base64::encode(test_id.as_slice()), 
                        base64::encode(bcast_id)
                    )
                }
                let delay = Version::get() - bcast.date;
                if delay > 1 {
                    log::warn!(
                        target: TARGET, 
                        "Received overlay broadcast {} ({} bytes) in {} seconds", 
                        base64::encode(bcast_id), 
                        ret.len(),
                        delay
                    )
                } else {
                    log::trace!(
                        target: TARGET, 
                        "Received overlay broadcast {} ({} bytes) in {} seconds", 
                        base64::encode(bcast_id), 
                        ret.len(),
                        delay
                    )
                }
                ret
            };
            Ok(Some(ret))
        } else {
            Ok(None)
        }

    }

    async fn receive_broadcast(
        overlay_shard: &Arc<Self>, 
        bcast: BroadcastOrd,
        raw_data: &[u8],
        peers: &AdnlPeers
    ) -> Result<()> {
        if overlay_shard.is_broadcast_outdated(bcast.date, peers.other()) {          
            return Ok(())
        }
        let src_key = KeyOption::from_tl_public_key(&bcast.src)?;
        let src = if (bcast.flags & Self::FLAG_BCAST_ANY_SENDER) != 0 {
            [0u8; 32]
        } else {                           
            *src_key.id().data()
        };
        #[cfg(not(feature = "compression"))]
        let ton::bytes(data) = bcast.data;
        #[cfg(feature = "compression")]
        let data = DataCompression::decompress(&bcast.data)?;
        let signature = Self::calc_broadcast_to_sign(&data[..], bcast.date, src)?;
        let bcast_id = if let Some(bcast_id) = overlay_shard.calc_broadcast_id(&signature)? {
            bcast_id
        } else {
            return Ok(());
        };
        src_key.verify(&signature, &bcast.signature.0)?;
        log::trace!(target: TARGET, "Received overlay broadcast, {} bytes", data.len());
        #[cfg(feature = "telemetry")]
        if data.len() >= 4 {
            log::info!(
                target: TARGET_BROADCAST,
                "Broadcast trace: recv ordinary {} {} bytes, tag {:08x} to overlay {}",
                base64::encode(&bcast_id),  
                data.len(),
                u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
                overlay_shard.overlay_id
            );
        }
        BroadcastReceiver::push(
            &overlay_shard.received_rawbytes, 
            BroadcastRecvInfo {
                packets: 1,
                data,
                recv_from: src_key.id().clone()
            }
        );
        let options = overlay_shard.options.load(Ordering::Relaxed);
        if (options & OverlayShard::OPTION_DISABLE_BROADCAST_RETRANSMIT) == 0 {
            let neighbours = overlay_shard.neighbours.random_vec(Some(peers.other()), 3);
            // Transit broadcasts will be traced untagged 
            overlay_shard.distribute_broadcast(
                &TaggedByteSlice {
                    object: raw_data, 
                    #[cfg(feature = "telemetry")]
                    tag: overlay_shard.tag_broadcast_ord
                },
                peers.local(),
                &neighbours,
            ).await?;
        }
        Self::setup_broadcast_purge(overlay_shard, bcast_id);
        Ok(())
    }

    async fn receive_fec_broadcast(
        overlay_shard: &Arc<Self>, 
        bcast: BroadcastFec,
        raw_data: &[u8],
        peers: &AdnlPeers 
    ) -> Result<()> {
        if overlay_shard.is_broadcast_outdated(bcast.date, peers.other()) {          
            return Ok(())
        }
        let bcast_id = get256(&bcast.data_hash);
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: recv FEC {} {} bytes to overlay {}",
            base64::encode(bcast_id),  
            raw_data.len(),
            overlay_shard.overlay_id
        );
        #[cfg(feature = "telemetry")]
        let stats = if let Some(stats) = overlay_shard.stats_per_transfer.get(bcast_id) {
            stats
        } else {
            add_counted_object_to_map(
                &overlay_shard.stats_per_transfer,
                bcast_id.clone(),
                || {
                    let ret = TransferStats {
                        income: AtomicU64::new(0),
                        passed: AtomicU64::new(0),
                        resent: AtomicU64::new(0),
                        counter: overlay_shard.allocated.stats_transfer.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    overlay_shard.telemetry.stats_transfer.update(
                        overlay_shard.allocated.stats_transfer.load(Ordering::Relaxed)
                    );
                    Ok(ret)
                }
            )?;
            overlay_shard.stats_per_transfer.get(bcast_id).ok_or_else(
                || error!("INTERNAL ERROR: Cannot count transfer statistics")
            )?
        };
        #[cfg(feature = "telemetry")]
        stats.val().income.fetch_add(1, Ordering::Relaxed);
        let transfer = loop {
            if let Some(transfer) = overlay_shard.owned_broadcasts.get(bcast_id) {
                break transfer
            }
            if !add_unbound_object_to_map(
                &overlay_shard.owned_broadcasts, 
                *bcast_id,
                || Ok(OwnedBroadcast::WillBeRecvFec)
            )? {
                tokio::task::yield_now().await;
                continue;
            }
            let transfer = Self::create_fec_recv_transfer(overlay_shard, &bcast);
            if transfer.is_err() {
                overlay_shard.owned_broadcasts.remove(bcast_id);
            }
            let transfer = OwnedBroadcast::RecvFec(transfer?);
            let ok = match overlay_shard.owned_broadcasts.insert(*bcast_id, transfer) {
                Some(removed) => matches!(removed.val(), OwnedBroadcast::WillBeRecvFec),
                _ => false
            };
            if !ok {
                log::error!(  
                    target: TARGET, 
                    "INTERNAL ERROR: recv FEC broadcast {} creation mismatch in overlay {}",
                    base64::encode(bcast_id),
                    overlay_shard.overlay_id
                )
            }
        };
        let transfer = transfer.val();
        let transfer = if let OwnedBroadcast::RecvFec(transfer) = transfer {
            transfer
        } else {
            // Not a receive FEC broadcast 
            return Ok(())
        };
        transfer.updated_at.refresh();
        if &transfer.source != KeyOption::from_tl_public_key(&bcast.src)?.id() {
            log::warn!(
                target: TARGET, 
                "Same broadcast {} but parts from different sources",
                base64::encode(bcast_id)            
            );
            return Ok(())
        }
        if !transfer.history.update(bcast.seqno as u64, TARGET_BROADCAST).await? {
            return Ok(())
        }
        #[cfg(feature = "telemetry")]
        stats.val().passed.fetch_add(1, Ordering::Relaxed);
        if !transfer.completed.load(Ordering::Relaxed) {
            transfer.sender.send(Some(bcast))?;
        }
        let options = overlay_shard.options.load(Ordering::Relaxed);
        if (options & OverlayShard::OPTION_DISABLE_BROADCAST_RETRANSMIT) == 0 {
            let neighbours = overlay_shard.neighbours.random_vec(Some(peers.other()), 5);
            #[cfg(feature = "telemetry")]
            stats.val().resent.fetch_add(neighbours.len() as u64, Ordering::Relaxed);
            // Transit broadcasts will be traced untagged 
            overlay_shard.distribute_broadcast(
                &TaggedByteSlice {
                    object: raw_data, 
                    #[cfg(feature = "telemetry")]
                    tag: overlay_shard.tag_broadcast_fec
                },
                peers.local(),
                &neighbours,
            ).await?;
        }
        Ok(())
    }

    async fn send_broadcast(
        overlay_shard: &Arc<Self>, 
        data: &TaggedByteSlice<'_>, 
        source: &Arc<KeyOption>,
        overlay_key: &Arc<KeyId>
    ) -> Result<BroadcastSendInfo> {                                                        
        let date = Version::get();
        let signature = Self::calc_broadcast_to_sign(data.object, date, [0u8; 32])?;
        let bcast_id = if let Some(bcast_id) = overlay_shard.calc_broadcast_id(&signature)? {
            bcast_id
        } else {
            log::warn!(target: TARGET, "Trying to send duplicated broadcast");
            return Ok(BroadcastSendInfo::default())
        };
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
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: send ordinary {} {} bytes, tag {:08x} to overlay {}",
            base64::encode(&bcast_id),  
            data.object.len(),
            data.tag,
            overlay_shard.overlay_id
        );
        #[cfg(not(feature = "compression"))]
        let data_body = data.object.to_vec();
        #[cfg(feature = "compression")]
        let data_body = DataCompression::compress(data.object)?;
        let signature = source.sign(&signature)?;
        let bcast = BroadcastOrd {
            src: source.into_tl_public_key()?,
            certificate: OverlayCertificate::Overlay_EmptyCertificate,
            flags: Self::FLAG_BCAST_ANY_SENDER,
            data: ton::bytes(data_body),
            date,
            signature: ton::bytes(signature.to_vec())
        }.into_boxed();                                   
        let mut buf = overlay_shard.message_prefix.clone();
        serialize_append(&mut buf, &bcast)?;
        let neighbours = overlay_shard.neighbours.random_vec(None, 3);
        overlay_shard.distribute_broadcast(
            &TaggedByteSlice {
                object: &buf, 
                #[cfg(feature = "telemetry")]
                tag: data.tag
            },
            overlay_key,
            &neighbours,
        ).await?;
        Self::setup_broadcast_purge(overlay_shard, bcast_id);
        let ret = BroadcastSendInfo {
            packets: 1,
            send_to: neighbours.len() as u32
        };
        Ok(ret)
    } 

    fn setup_broadcast_purge(overlay_shard: &Arc<Self>, bcast_id: BroadcastId) {
        let overlay_shard = overlay_shard.clone();
        tokio::spawn(
            async move {
                tokio::time::sleep(Duration::from_secs(Self::TIMEOUT_BROADCAST)).await;
                overlay_shard.purge_broadcasts_count.fetch_add(1, Ordering::Relaxed);
                overlay_shard.purge_broadcasts.push(bcast_id);
            }
        );
    }

    fn update_neighbours(&self, n: u32) -> Result<()> {
        if self.overlay_key.is_some() {
            self.known_peers.random_set(&self.neighbours, None, n)
        } else {
            self.random_peers.random_set(&self.neighbours, Some(&self.bad_peers), n)
        }
    }

    fn update_random_peers(&self, n: u32) -> Result<()> {
        self.known_peers.random_set(&self.random_peers, Some(&self.bad_peers), n)?;
        self.update_neighbours(OverlayNode::MAX_SHARD_NEIGHBOURS)
    }

    #[cfg(feature = "telemetry")]
    fn print_stats(&self) -> Result<()> {
        let elapsed = self.start.elapsed().as_secs();
        if elapsed == 0 {
            // Too early to print stats
            return Ok(())
        }
        let messages_recv = self.messages_recv.load(Ordering::Relaxed);
        let messages_send = self.messages_send.load(Ordering::Relaxed);
        log::info!(
            target: TARGET,
            "------- OVERLAY STAT send {}: {} messages, {} messages/sec average load",
            self.overlay_id, messages_send, messages_send / elapsed
        );
        for dst in self.stats_per_peer_send.iter() {
            log::info!(
                target: TARGET, 
                "  -- OVERLAY STAT send {} to {}", 
                self.overlay_id, dst.key()
            );
            for tag in dst.val().iter() {
                let count = tag.val().count.load(Ordering::Relaxed);
                if count / elapsed < 1 {
                    continue
                }
                log::info!(
                    target: TARGET, 
                    "  OVERLAY STAT send {} tag {:x}: {}, {} per sec average load", 
                    self.overlay_id, tag.key(), count, count / elapsed
                );
            }
        }
        log::info!(
            target: TARGET,
            "------- OVERLAY STAT recv {}: {} messages, {} messages/sec average load",
            self.overlay_id, messages_recv, messages_recv / elapsed
        );
        for dst in self.stats_per_peer_recv.iter() {
            log::info!(
                target: TARGET, 
                "  -- OVERLAY STAT recv {} from {}", 
                self.overlay_id, dst.key()
            );
            for tag in dst.val().iter() {
                let count = tag.val().count.load(Ordering::Relaxed);
                if count / elapsed < 1 {
                    continue;
                }
                log::info!(
                    target: TARGET, 
                    "  OVERLAY STAT recv {} tag {:x}: {}, {} per sec average load", 
                    self.overlay_id, tag.key(), count, count / elapsed
                );
            }
        }
        let mut inc = 0;
        let mut pas = 0;
        let mut res = 0;
        for transfer in self.stats_per_transfer.iter() {
            inc += transfer.val().income.load(Ordering::Relaxed);
            pas += transfer.val().passed.load(Ordering::Relaxed);
            res += transfer.val().resent.load(Ordering::Relaxed);
/*
            log::info!(
                target: TARGET, 
                "  ** OVERLAY STAT resend transfer {}: -> {} / {} -> {}", 
                base64::encode(transfer.key()), 
                transfer.val().income.load(Ordering::Relaxed),
                transfer.val().passed.load(Ordering::Relaxed),
                transfer.val().resent.load(Ordering::Relaxed)
            )
*/
        }
        log::info!(
            target: TARGET, 
            "  ** OVERLAY STAT resend {} / {} -> {}", 
            inc, pas, res
        );
        let map = lockfree::map::Map::new();
        for transfer in self.owned_broadcasts.iter() {
            if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                if transfer.updated_at.is_expired(5) {
                    continue
                }
                let mut tag = transfer.telemetry.tag.load(Ordering::Relaxed);
                let flags = transfer.telemetry.flags.load(Ordering::Relaxed);
                if (flags & RecvTransferFecTelemetry::FLAG_RECEIVED) == 0 {
                    tag |= flags;
                }
                add_unbound_object_to_map(
                    &map,
                    tag,
                    || Ok((AtomicU32::new(0), AtomicU32::new(0)))
                )?;
                if let Some(item) = map.get(&tag) {
                   let (cnt, len) = item.val();
                   cnt.fetch_add(1, Ordering::Relaxed);
                   len.fetch_add(
                       transfer.telemetry.len.load(Ordering::Relaxed), 
                       Ordering::Relaxed
                   );
                }
            }
        }
        for item in map.iter() {
            let (cnt, len) = item.val();
            let cnt = cnt.load(Ordering::Relaxed);
            let len = len.load(Ordering::Relaxed) / cnt;
            log::info!(
                target: TARGET, 
                "  ** OVERLAY STAT resend by tag {:x}: {}, {} bytes avg", 
                item.key(), cnt, len
            )
        }
        Ok(())
    }

    #[cfg(feature = "telemetry")]
    fn update_stats(&self, dst: &Arc<KeyId>, tag: u32, is_send: bool) -> Result<()> {
        let stats = if is_send {
            &self.stats_per_peer_send
        } else {
            &self.stats_per_peer_recv
        };
        let stats = if let Some(stats) = stats.get(dst) {
            stats 
        } else {
            add_unbound_object_to_map(
                stats,
                dst.clone(),
                || Ok(lockfree::map::Map::new())
            )?;
            if let Some(stats) = stats.get(dst) {
                stats
            } else {
                fail!(
                    "INTERNAL ERROR: cannot add overlay statistics for {}:{}", 
                    self.overlay_id, dst
                )
            }
        };
        let stats = if let Some(stats) = stats.val().get(&tag) {
            stats
        } else {
            add_counted_object_to_map(
                stats.val(),
                tag,
                || {
                    let ret = PeerStats {
                        count: AtomicU64::new(0),
                        counter: self.allocated.stats_peer.clone().into()
                    };
                    #[cfg(feature = "telemetry")]
                    self.telemetry.stats_peer.update(
                        self.allocated.stats_peer.load(Ordering::Relaxed)
                    );
                    Ok(ret)
                }
            )?;
            if let Some(stats) = stats.val().get(&tag) {
                stats
            } else {
                fail!(
                    "INTERNAL ERROR: cannot add overlay statistics for {}:{}:{}", 
                    self.overlay_id, dst, tag
                )
            }
        };
        stats.val().count.fetch_add(1, Ordering::Relaxed);
        if is_send {
            self.messages_send.fetch_add(1, Ordering::Relaxed);
        } else {
            self.messages_recv.fetch_add(1, Ordering::Relaxed);
        }
        let elapsed = self.start.elapsed().as_secs();
        if elapsed > self.print.load(Ordering::Relaxed) {
            self.print.store(elapsed + 5, Ordering::Relaxed);
            self.print_stats()?;
        }
        Ok(())
    }

}

#[cfg(feature = "telemetry")]
struct RecvTransferFecTelemetry {
    flags: AtomicU32,
    len: AtomicU32, 
    tag: AtomicU32 
}

#[cfg(feature = "telemetry")]
impl RecvTransferFecTelemetry {
    const FLAG_RECEIVE_STARTED: u32 = 0x01;
    const FLAG_RECEIVED: u32        = 0x02;
    const FLAG_FAILED: u32          = 0x04;
}

declare_counted!(
    struct RecvTransferFec {
        completed: AtomicBool,
        history: PeerHistory,
        sender: tokio::sync::mpsc::UnboundedSender<Option<BroadcastFec>>,
        source: Arc<KeyId>,
        #[cfg(feature = "telemetry")]
        telemetry: RecvTransferFecTelemetry,
        updated_at: UpdatedAt
    }
);

declare_counted!(
    struct SendTransferFec {
        bcast_id: BroadcastId,
        encoder: RaptorqEncoder,
        seqno: u32
    }
);

#[async_trait::async_trait]
pub trait QueriesConsumer: Send + Sync {
    async fn try_consume_query(&self, query: TLObject, peers: &AdnlPeers) -> Result<QueryResult>;
}

declare_counted!(
    struct ConsumerObject {
        object: Arc<dyn QueriesConsumer>
    }
);

struct OverlayAlloc {
    consumers: Arc<AtomicU64>,
    overlays: Arc<AtomicU64>,
    peers: Arc<AtomicU64>,
    recv_transfers: Arc<AtomicU64>,
    send_transfers: Arc<AtomicU64>,
    #[cfg(feature = "telemetry")]
    stats_peer: Arc<AtomicU64>,
    #[cfg(feature = "telemetry")]
    stats_transfer: Arc<AtomicU64>
}

#[cfg(feature = "telemetry")]
struct OverlayTelemetry {
    consumers: Arc<Metric>,
    overlays: Arc<Metric>,
    peers: Arc<Metric>,
    recv_transfers: Arc<Metric>,
    send_transfers: Arc<Metric>,
    stats_peer: Arc<Metric>,
    stats_transfer: Arc<Metric>
}

/// Overlay Node
pub struct OverlayNode {
    adnl: Arc<AdnlNode>,
    consumers: lockfree::map::Map<Arc<OverlayShortId>, ConsumerObject>,
    options: Arc<AtomicU32>,
    node_key: Arc<KeyOption>, 
    shards: lockfree::map::Map<Arc<OverlayShortId>, Arc<OverlayShard>>,     
    zero_state_file_hash: [u8; 32],
    #[cfg(feature = "telemetry")]
    tag_get_random_peers: u32,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<OverlayTelemetry>,
    allocated: Arc<OverlayAlloc>    
}

impl OverlayNode {

    const MAX_BROADCAST_LOG: u32 = 1000;
    const MAX_PEERS: u32 = 65536;
    const MAX_RANDOM_PEERS: u32 = 4;
    const MAX_SHARD_NEIGHBOURS: u32 = 5;
    const MAX_SHARD_PEERS: u32 = 20;
    const MAX_SIZE_ORDINARY_BROADCAST: usize = 768;
    const TIMEOUT_GC: u64 = 1000; // Milliseconds
    const TIMEOUT_PEERS: u64 = 60000; // Milliseconds

    /// Constructor 
    pub fn with_adnl_node_and_zero_state(
        adnl: Arc<AdnlNode>, 
        zero_state_file_hash: &[u8; 32],
        key_tag: usize
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        #[cfg(feature = "telemetry")]
        let telemetry = OverlayTelemetry {
            consumers: adnl.add_metric("Alloc OVRL consumers"),
            overlays: adnl.add_metric("Alloc OVRL shards"),
            peers: adnl.add_metric("Alloc OVRL peers"),
            recv_transfers: adnl.add_metric("Alloc OVRL recv transfers"),
            send_transfers: adnl.add_metric("Alloc OVRL send transfers"),
            stats_peer: adnl.add_metric("Alloc OVRL peer stats"),
            stats_transfer: adnl.add_metric("Alloc OVRL transfer stats"),            
        };
        let allocated = OverlayAlloc {
            consumers: Arc::new(AtomicU64::new(0)),
            overlays: Arc::new(AtomicU64::new(0)),
            peers: Arc::new(AtomicU64::new(0)),
            recv_transfers: Arc::new(AtomicU64::new(0)),
            send_transfers: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "telemetry")]
            stats_peer: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "telemetry")]
            stats_transfer: Arc::new(AtomicU64::new(0))
        };
        let ret = Self { 
            adnl,
            options: Arc::new(AtomicU32::new(0)),
            consumers: lockfree::map::Map::new(),
            node_key,                   
            shards: lockfree::map::Map::new(),
            zero_state_file_hash: *zero_state_file_hash,
            #[cfg(feature = "telemetry")]
            tag_get_random_peers: tag_from_boxed_type::<GetRandomPeers>(),
            #[cfg(feature = "telemetry")]
            telemetry: Arc::new(telemetry),
            allocated: Arc::new(allocated)
        };
        Ok(Arc::new(ret))
    }

    /// Add overlay query consumer
    pub fn add_consumer(
        &self, 
        overlay_id: &Arc<OverlayShortId>, 
        consumer: Arc<dyn QueriesConsumer>
    ) -> Result<bool> {
        log::debug!(target: TARGET, "Add consumer {} to overlay", overlay_id);
        add_counted_object_to_map(
            &self.consumers,
            overlay_id.clone(),
            || {
                let ret = ConsumerObject {
                    object: consumer.clone(),
                    counter: self.allocated.consumers.clone().into()
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.consumers.update(
                    self.allocated.consumers.load(Ordering::Relaxed)
                );
                Ok(ret)
            }
        )
    }

    /// Add private_overlay
    pub fn add_private_overlay(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>,
        overlay_key: &Arc<KeyOption>, 
        peers: &[Arc<KeyId>]
    ) -> Result<bool> {
        if self.add_overlay(runtime, overlay_id, Some(overlay_key.clone()))? {
            let shard = self.get_shard(overlay_id, "Cannot add the private overlay")?;
            let our_key = overlay_key.id();
            for peer in peers {
                if peer == our_key {
                    continue
                }
                shard.known_peers.put(peer.clone())?;
            }
            shard.update_neighbours(Self::MAX_SHARD_NEIGHBOURS)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Add private overlay peers 
    pub fn add_private_peers(
        &self, 
        local_adnl_key: &Arc<KeyId>, 
        peers: Vec<(IpAddress, KeyOption)>
    ) -> Result<Vec<Arc<KeyId>>> {
        let mut ret = Vec::new();
        for (ip, key) in peers {
            if let Some(peer) = self.adnl.add_peer(local_adnl_key, &ip, &Arc::new(key))? {
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
        let shard = self.get_shard(overlay_id, "Trying add peer to unknown public overlay")?;
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
        shard.bad_peers.remove(&ret);
        shard.known_peers.put(ret.clone())?;
        if shard.random_peers.count() < Self::MAX_SHARD_PEERS {
            shard.random_peers.put(ret.clone())?;
        }            
        if shard.neighbours.count() < Self::MAX_SHARD_NEIGHBOURS {
            shard.neighbours.put(ret.clone())?;
        }  
        add_counted_object_to_map_with_update(
            &shard.nodes,
            ret.clone(),
            |old_node| {
                if let Some(old_node) = old_node {
                    if old_node.object.version >= peer.version {
                        return Ok(None)
                    }
                }
                let ret = NodeObject {
                    object: peer.clone(),
                    counter: self.allocated.peers.clone().into()
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.peers.update(
                    self.allocated.peers.load(Ordering::Relaxed)
                );
                Ok(Some(ret))
            }
        )?;
        Ok(Some(ret))
    }

    /// Add shard
    pub fn add_shard(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<bool> {
        self.add_overlay(runtime, overlay_id, None)
    }

    /// Broadcast message 
    pub async fn broadcast(
        &self,
        overlay_id: &Arc<OverlayShortId>, 
        data: &TaggedByteSlice<'_>, 
        source: Option<&Arc<KeyOption>>
    ) -> Result<BroadcastSendInfo> {
        log::trace!(target: TARGET, "Broadcast {} bytes", data.object.len());
        let shard = self.get_shard(overlay_id, "Trying broadcast to unknown overlay")?;
        let source = source.unwrap_or(&self.node_key);
        let overlay_key = shard.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        if data.object.len() <= Self::MAX_SIZE_ORDINARY_BROADCAST {
            OverlayShard::send_broadcast(&shard, data, source, overlay_key).await
        } else {
            OverlayShard::create_fec_send_transfer(&shard, data, source, overlay_key)
        }
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
        log::debug!(target: TARGET, "Delete private overlay {}", overlay_id);
        if let Some(shard) = self.shards.get(overlay_id) {
            let shard = shard.val();
            shard.overlay_key.as_ref().ok_or_else(
                || error!("Try to delete public overlay {}", overlay_id)
            )?; 
            if let Some(received_catchain) = shard.received_catchain.as_ref() {
                BroadcastReceiver::stop(received_catchain)
            }
            BroadcastReceiver::stop(&shard.received_peers);
            BroadcastReceiver::stop(&shard.received_rawbytes);
            self.shards.remove(overlay_id);
            log::debug!(target: TARGET, "Delete consumer {} from private overlay", overlay_id);
            self.consumers.remove(overlay_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete private overlay peers 
    pub fn delete_private_peers(
        &self, 
        local_key: &Arc<KeyId>, 
        peers: &[Arc<KeyId>]
    ) -> Result<bool> {
        let mut ret = false;
        for peer in peers {               
            ret = self.adnl.delete_peer(local_key, peer)? || ret
        }    
        Ok(ret)
    }

    /// Delete public overlay peer 
    pub fn delete_public_peer(
        &self, 
        peer: &Arc<KeyId>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<bool> {
        let shard = self.get_shard(
            overlay_id,
            "Trying to delete peer from unknown public overlay"
        )?;
        if shard.overlay_key.is_some() {
            fail!("Trying to delete public peer from private overlay {}", overlay_id)
        }
        match shard.bad_peers.insert_with(peer.clone(), |_, prev| prev.is_none()) {
            lockfree::set::Insertion::Created => (),      
            _ => return Ok(false)
        }
        if shard.random_peers.contains(peer) {
            shard.update_random_peers(Self::MAX_SHARD_PEERS)?
        }
        // DO NOT DELETE from ADNL, because it may be shared between overlays
        // self.adnl.delete_peer(self.node_key.id(), peer)
        Ok(true)
    }

    /// Get debug trace
    pub fn get_debug_trace(&self, overlay_id: &Arc<OverlayShortId>) -> Result<u32> {
        let shard = self.get_shard(overlay_id, "Getting trace from unknown overlay")?;
        Ok(shard.debug_trace.load(Ordering::Relaxed))
    }

    /// Get locally cached random peers
    pub fn get_cached_random_peers(
        &self,
        dst: &AddressCache,  
        overlay_id: &Arc<OverlayShortId>, 
        n: u32
    ) -> Result<()> {
        let shard = self.get_shard(
            overlay_id, 
            "Getting cached random peers from unknown overlay"
        )?;
        shard.known_peers.random_set(dst, Some(&shard.bad_peers), n)
    }

    /// Get query prefix
    pub fn get_query_prefix(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Vec<u8>> {
        let shard = self.get_shard(overlay_id, "Getting query prefix of unknown overlay")?;
        Ok(shard.query_prefix.clone())
    }
    
    /// overlay.GetRandomPeers
    pub async fn get_random_peers(
        &self, 
        dst: &Arc<KeyId>, 
        overlay_id: &Arc<OverlayShortId>,
        timeout: Option<u64>
    ) -> Result<Option<Vec<Node>>> {
        let shard = self.get_shard(overlay_id, "Getting random peers from unknown overlay")?;
        log::trace!(target: TARGET, "Get random peers from {}", dst);
        let query = GetRandomPeers {
            peers: self.prepare_random_peers(&shard)?
        };
        let query = TaggedTlObject {
            object: TLObject::new(query),
            #[cfg(feature = "telemetry")]
            tag: self.tag_get_random_peers
        };
        let answer = self.query(dst, &query, overlay_id, timeout).await?;
        if let Some(answer) = answer {
            let answer: NodesBoxed = Query::parse(answer, &query.object)?;
            log::trace!(target: TARGET, "Got random peers from {}", dst);
            Ok(Some(self.process_random_peers(overlay_id, answer.only())?))
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
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<()> {
        let shard = self.get_shard(overlay_id, "Sending ADNL message to unknown overlay")?;
        let src = shard.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")]
        shard.update_stats(dst, data.tag, true)?;
        let mut buf = shard.message_prefix.clone();
        buf.extend_from_slice(data.object);
        self.adnl.send_custom(
            &TaggedByteSlice {
                object: &buf, 
                #[cfg(feature = "telemetry")]
                tag: data.tag
            },
            peers
        )
    }

    /// Send query via ADNL
    pub async fn query(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TaggedTlObject,
        overlay_id: &Arc<OverlayShortId>,
        timeout: Option<u64>
    ) -> Result<Option<TLObject>> {
        let shard = self.get_shard(overlay_id, "Sending ADNL query to unknown overlay")?;
        let src = shard.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")] 
        shard.update_stats(dst, query.tag, true)?;
        self.adnl.clone().query_with_prefix(
            Some(&shard.query_prefix), 
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
        data: &TaggedByteSlice<'_>,
        max_answer_size: Option<i64>,
        roundtrip: Option<u64>,
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let shard = self.get_shard(overlay_id, "Sending RLDP query to unknown overlay")?;
        let src = shard.overlay_key.as_ref().unwrap_or(&self.node_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")]
        shard.update_stats(dst, data.tag, true)?;
        rldp.query(data, max_answer_size, &peers, roundtrip).await
    }

    /// Enable/disable broadcast retransmit
    pub fn set_broadcast_retransmit(&self, enabled: bool) {
        if enabled {
            self.options.fetch_and(
                !OverlayShard::OPTION_DISABLE_BROADCAST_RETRANSMIT, 
                Ordering::Relaxed
            );
        } else {
            self.options.fetch_or(
                OverlayShard::OPTION_DISABLE_BROADCAST_RETRANSMIT, 
                Ordering::Relaxed
            );
        }
    } 

    /// Statistics
    #[cfg(feature = "telemetry")]
    pub fn stats(&self) -> Result<()> {
        for shard in self.shards.iter() {
            shard.val().print_stats()?
        }
        Ok(())
    } 
    
    /// Wait for broadcast
    pub async fn wait_for_broadcast(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<BroadcastRecvInfo>> {
        self.get_shard(overlay_id, "Waiting for broadcast in unknown overlay")?
            .received_rawbytes.pop().await
    }

    /// Wait for catchain
    pub async fn wait_for_catchain(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<(CatchainBlockUpdate, ValidatorSessionBlockUpdate, Arc<KeyId>)>> {
        self.get_shard(overlay_id, "Waiting for catchain in unknown overlay")?
            .received_catchain.as_ref().ok_or_else(
                || error!("Waiting for catchain in public overlay {}", overlay_id)
            )?.pop().await
    }

    /// Wait for peers
    pub async fn wait_for_peers(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Option<Vec<Node>>> {
        self.get_shard(overlay_id, "Waiting for peers in unknown overlay")?
            .received_peers.pop().await
    }

    fn add_overlay(
        &self, 
        runtime: Option<tokio::runtime::Handle>,
        overlay_id: &Arc<OverlayShortId>, 
        overlay_key: Option<Arc<KeyOption>>
    ) -> Result<bool> {
        log::debug!(target: TARGET, "Add overlay {} to node", overlay_id);
        let added = add_counted_object_to_map(
            &self.shards,
            overlay_id.clone(), 
            || {
                let message_prefix = OverlayMessage {
                    overlay: ton::int256(*overlay_id.data())
                }.into_boxed();
                let query_prefix = OverlayQuery {
                    overlay: ton::int256(*overlay_id.data())
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
                    bad_peers: lockfree::set::Set::new(),
                    known_peers: AddressCache::with_limit(Self::MAX_PEERS),
                    message_prefix: serialize(&message_prefix)?,
                    neighbours: AddressCache::with_limit(Self::MAX_SHARD_NEIGHBOURS), 
                    nodes: lockfree::map::Map::new(),
                    options: self.options.clone(),
                    overlay_id: overlay_id.clone(),
                    overlay_key: overlay_key.clone(),
                    owned_broadcasts: lockfree::map::Map::new(),
                    purge_broadcasts: lockfree::queue::Queue::new(),
                    purge_broadcasts_count: AtomicU32::new(0),
                    query_prefix: serialize(&query_prefix)?,
                    random_peers: AddressCache::with_limit(Self::MAX_SHARD_PEERS),
                    received_catchain,
                    received_peers: Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0)
                        }
                    ),
                    received_rawbytes: Arc::new(
                        BroadcastReceiver {
                            data: lockfree::queue::Queue::new(),
                            subscribers: lockfree::queue::Queue::new(),
                            synclock: AtomicU32::new(0)
                        }
                    ),
                    #[cfg(feature = "telemetry")]
                    start: Instant::now(),
                    #[cfg(feature = "telemetry")]
                    print: AtomicU64::new(0),
                    #[cfg(feature = "telemetry")]
                    messages_recv: AtomicU64::new(0),
                    #[cfg(feature = "telemetry")]
                    messages_send: AtomicU64::new(0),
                    #[cfg(feature = "telemetry")]  
                    stats_per_peer_recv: lockfree::map::Map::new(),
                    #[cfg(feature = "telemetry")]  
                    stats_per_peer_send: lockfree::map::Map::new(),
                    #[cfg(feature = "telemetry")]  
                    stats_per_transfer: lockfree::map::Map::new(),
                    #[cfg(feature = "telemetry")]
                    tag_broadcast_fec: tag_from_unboxed_type::<BroadcastFec>(),
                    #[cfg(feature = "telemetry")]
                    tag_broadcast_ord: tag_from_unboxed_type::<BroadcastOrd>(),
                    #[cfg(feature = "telemetry")]
                    telemetry: self.telemetry.clone(), 
                    allocated: self.allocated.clone(),
                    debug_trace: AtomicU32::new(0),
                    counter: self.allocated.overlays.clone().into()
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.overlays.update(
                    self.allocated.overlays.load(Ordering::Relaxed)
                );
                shard.update_neighbours(Self::MAX_SHARD_NEIGHBOURS)?;
                Ok(Arc::new(shard))
            }
        )?;
        if added {
            let shard = self.get_shard(overlay_id, "Cannot add overlay")?;
            let handle = runtime.unwrap_or_else(tokio::runtime::Handle::current);
            handle.spawn(
                async move {
                    let mut timeout_peers = 0;
                    while Arc::strong_count(&shard) > 1 {
                        let upto = Self::MAX_BROADCAST_LOG;
                        while shard.purge_broadcasts_count.load(Ordering::Relaxed) > upto {
                            if let Some(bcast_id) = shard.purge_broadcasts.pop() {
                                shard.owned_broadcasts.remove(&bcast_id);
                                #[cfg(feature = "telemetry")]
                                shard.stats_per_transfer.remove(&bcast_id);
                            }
                            shard.purge_broadcasts_count.fetch_sub(1, Ordering::Relaxed);
                        }
                        timeout_peers += Self::TIMEOUT_GC;
                        if timeout_peers > Self::TIMEOUT_PEERS {
                            let result = if shard.overlay_key.is_some() {
                                shard.update_neighbours(1)
                            } else {
                                shard.update_random_peers(1)
                            };
                            if let Err(e) = result {
                                log::error!(target: TARGET, "Error: {}", e)
                            }
                            timeout_peers = 0;
                        }
                        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_GC)).await;
                    }
                }
            );
        }
        Ok(added)
    }

    fn get_shard(&self, overlay_id: &Arc<OverlayShortId>, msg: &str) -> Result<Arc<OverlayShard>> {
        let ret = self.shards.get(overlay_id).ok_or_else(
            || error!("{} {}", msg, overlay_id)
        )?.val().clone();
        Ok(ret)
    }

    fn prepare_random_peers(&self, shard: &OverlayShard) -> Result<Nodes> {
        let mut ret = vec![self.sign_local_node(&shard.overlay_id)?];
        let nodes = AddressCache::with_limit(Self::MAX_RANDOM_PEERS);
        shard.random_peers.random_set(&nodes, None, Self::MAX_RANDOM_PEERS)?;
        let (mut iter, mut current) = nodes.first();
        while let Some(node) = current {
            if let Some(node) = shard.nodes.get(&node) {
                ret.push(node.val().object.clone())
            }
            current = nodes.next(&mut iter)
        }
        let ret = Nodes {
            nodes: ret.into()
        };
        Ok(ret)
    }

    fn process_random_peers(
        &self, 
        overlay_id: &Arc<OverlayShortId>, 
        peers: Nodes
    ) -> Result<Vec<Node>> {
        let mut ret = Vec::new();
        log::trace!(target: TARGET, "-------- Got random peers:");
        let mut peers = peers.nodes.0;
        while let Some(peer) = peers.pop() {
            if self.node_key.id().data() == KeyOption::from_tl_public_key(&peer.id)?.id().data() {
                continue
            }
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
        let peers = self.process_random_peers(&shard.overlay_id, query.peers)?;
        BroadcastReceiver::push(&shard.received_peers, peers); 
        self.prepare_random_peers(shard)
    }

    fn sign_local_node(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Node> {
        let shard = self.get_shard(overlay_id, "Signing local node for unknown overlay")?;
        let key = shard.overlay_key.as_ref().unwrap_or(&self.node_key);
        let version = Version::get();
        let local_node = NodeToSign {
            id: AdnlShortId {
                id: ton::int256(*key.id().data())
            },
            overlay: ton::int256(*overlay_id.data()),
            version 
        }.into_boxed();     
        let local_node = Node {
            id: key.into_tl_public_key()?,
            overlay: ton::int256(*overlay_id.data()),
            signature: ton::bytes(key.sign(&serialize(&local_node)?)?.to_vec()),
            version
        };     
        Ok(local_node)
    }

}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {
                                                           
    #[cfg(feature = "telemetry")]
    async fn poll(&self, _start: &Arc<Instant>) {
        self.telemetry.consumers.update(self.allocated.consumers.load(Ordering::Relaxed));
        self.telemetry.overlays.update(self.allocated.overlays.load(Ordering::Relaxed));
        self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));        
        self.telemetry.recv_transfers.update(
            self.allocated.recv_transfers.load(Ordering::Relaxed)
        );
        self.telemetry.send_transfers.update(
            self.allocated.send_transfers.load(Ordering::Relaxed)
        );
        self.telemetry.stats_peer.update(self.allocated.stats_peer.load(Ordering::Relaxed));        
        self.telemetry.stats_transfer.update(
            self.allocated.stats_transfer.load(Ordering::Relaxed)
        );
    }

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
        let overlay_shard = self.get_shard(&overlay_id, "Message to unknown overlay")?;
        #[cfg(feature = "telemetry")] {
            let (tag, _) = bundle[0].serialize_boxed();
            overlay_shard.update_stats(peers.other(), tag.0, false)?;
        }
        if bundle.len() == 2 {
            // Private overlay
            let catchain_update = match bundle.remove(0).downcast::<CatchainBlockUpdateBoxed>() {
                Ok(CatchainBlockUpdateBoxed::Catchain_BlockUpdate(upd)) => upd,
                Err(msg) => fail!("Unsupported private overlay message {:?}", msg)
            };
            let validator_session_update = 
                match bundle.remove(0).downcast::<ValidatorSessionBlockUpdateBoxed>() {
                    Ok(ValidatorSessionBlockUpdateBoxed::ValidatorSession_BlockUpdate(upd)) => upd,
                    Err(msg) => fail!("Unsupported private overlay message {:?}", msg)
                };
            let receiver = overlay_shard.received_catchain.as_ref().ok_or_else(
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
                    OverlayShard::receive_fec_broadcast(&overlay_shard, bcast, data, peers).await?;
                    Ok(true)
                },
                Ok(Broadcast::Overlay_Broadcast(bcast)) => {
                    OverlayShard::receive_broadcast(&overlay_shard, bcast, data, peers).await?;
                    Ok(true)
                },
                Ok(bcast) => fail!("Unsupported overlay broadcast message {:?}", bcast),
                Err(msg) => fail!("Unsupported overlay message {:?}", msg)
            }
        }
    }

    async fn try_consume_query_bundle(
        &self, 
        mut objects: Vec<TLObject>,
        peers: &AdnlPeers
    ) -> Result<QueryResult> {    
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
        #[cfg(feature = "telemetry")] 
        if let Some(overlay_shard) = self.shards.get(&overlay_id) {                                                      
            let (tag, _) = objects[0].serialize_boxed();
            overlay_shard.val().update_stats(peers.other(), tag.0, false)?;
        }
        let object = match objects.remove(0).downcast::<GetRandomPeers>() {
            Ok(query) => {                
                let overlay_shard = self.get_shard(&overlay_id, "Query to unknown overlay")?;
                return QueryResult::consume(
                    self.process_get_random_peers(&overlay_shard, query)?,
                    #[cfg(feature = "telemetry")]
                    None
                );
            }
            Err(object) => object
        };
        let consumer = if let Some(consumer) = self.consumers.get(&overlay_id) {
            consumer.val().object.clone()
        } else {
            fail!("No consumer for message in overlay {}", overlay_id)
        };
        match consumer.try_consume_query(object, peers).await {
            Err(msg) => fail!("Unsupported query, overlay: {}, query: {}", overlay_id, msg),
            r => r
        }
    }

}
