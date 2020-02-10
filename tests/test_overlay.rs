use sha2::Digest;

use dht::overlay::Overlay;

use std::{thread, time};
use std::{sync::Arc};

use adnl::{
    from_slice,
    common::{deserialize, KeyOption},
    node::{AdnlNode, AdnlNodeConfig}
};

use ton_api::{
    IntoBoxed, Serializer,
    ton::rpc::tonNode::GetNextKeyBlockIds as GetNextKeyBlockIds,
    ton::tonNode::blockidext::BlockIdExt as BlockIdExt
};

const ADNL_NODE0_CONFIG: &str = "{
    \"address\": \"0.0.0.0:4190\",
    \"key\": {
        \"type_id\": 1209251014,
        \"pvt_key\": \"Kz33UlpEtRRt+OVOfgfJASN79+zFjh2UsU5YUHsiDlg=\"
    }
}";

// azp002, overlay
const ADNL_NODE_COMPATIBILITY_CONFIG: &str = "{
    \"address\": \"13.52.162.184:30303\",
    \"key\": {
        \"type_id\": 1209251014,
        \"pub_key\": \"ccBetBO+46T/OZjPRlXkTdAIJD0Ca3KKEPReiB/cdX4=\"
    }
}";

fn create_overlay() -> (Arc<Overlay>, AdnlNodeConfig, tokio::runtime::Runtime) {
    let mut rt = init_test();
    let config_ours = AdnlNodeConfig::from_json(ADNL_NODE0_CONFIG, true).unwrap();
    let config_peer = AdnlNodeConfig::from_json(ADNL_NODE_COMPATIBILITY_CONFIG, false).unwrap();
    let adnl = rt.block_on(AdnlNode::with_config(config_ours)).unwrap();
    let overlay = Overlay::with_adnl_node(adnl.clone()).unwrap();
    rt.block_on(AdnlNode::start(&adnl, vec![overlay.clone()])).unwrap();
    (overlay, config_peer, rt)
}

#[test]
fn test_random_peers() {
    let (overlay, config_peer, mut rt) = create_overlay();
    rt.block_on(
        async move {
            thread::sleep(time::Duration::from_millis(200));
            println!("sending getRandomPeers request...");
            let peers = overlay.get_random_peers(config_peer.address()).await.unwrap();
            println!("received {} peers:", peers.len());
            assert!(peers.len() > 0);
            for node in peers {
                println!("{:?}", node);
            }
    	}
    )
}

fn get_zero_block_id() -> BlockIdExt {
    let workchain = -1;
    let shard = -9223372036854775808;
    let seqno = 529675;
    let root_hash = decode_int256("3c8baa9199e26bbaef1f7b9116e3466cbfc49af38724601a1736fbcb175e25c8");
    let file_hash = decode_int256("ba109bbcaabf4fcc8e75916d8e3c184d13ca6cf9a4494e7df7052a2b31f4cfa0");
        // TODO: try zero state hash
    BlockIdExt {workchain, shard, seqno, root_hash, file_hash}
}

#[test]
fn test_next_block_ids() {
    let (overlay, config_peer, mut rt) = create_overlay();
    rt.block_on(
        async move {
            let mut block = get_zero_block_id();
        
            thread::sleep(time::Duration::from_millis(200));
            println!("---- testing getNextBlockIds request...");
            
            for _ in 1..10 {
                let blocks = overlay.get_next_block_ids(block, 1, config_peer.address()).await.unwrap();
                assert!(blocks.len() == 1);
                block = blocks[0].clone();
                println!("{:?}", block);
                
                // let qqq = dht.download_block(block.clone(), config_peer.address()).await.unwrap();
                
                thread::sleep(time::Duration::from_millis(200));
            }
            
    	}
    )
}


fn init_test() -> tokio::runtime::Runtime {
    println!("");
    tokio::runtime::Runtime::new().unwrap()
}

fn decode_int256(s : &str) -> ton_api::ton::int256 {
    let vec = hex::decode(s).unwrap();
    ton_api::ton::int256(from_slice!(vec, 32))
}




fn calc_overlay_short_id(full_id : Vec<u8>) -> [u8; 32] {
    let public_key = ton_api::ton::pub_::publickey::Overlay{name: ton_api::ton::bytes(full_id)}.into_boxed();
    let mut buf = Vec::new();
    Serializer::new(&mut buf).write_boxed(&public_key).unwrap();
    let sha = &sha2::Sha256::digest(&buf.as_slice());
    from_slice!(sha, 32)
}

fn calc_overlay_id(workchain_id : i32, shard : i64, file_hash : &[u8; 32]) -> [u8; 32] {

    let type_id : i32 = 1302254377; // pub.Overlay

    let mut buf : Vec<u8> = Vec::new();
    buf.resize(4+4+8+32, 0);
    buf[0..4].copy_from_slice(&type_id.to_le_bytes());    
    buf[4..8].copy_from_slice(&workchain_id.to_le_bytes());    
    buf[8..16].copy_from_slice(&shard.to_le_bytes());
    buf[16..].copy_from_slice(file_hash);
    
    let hash = &sha2::Sha256::digest(buf.as_slice());
    let hash = hash.as_slice();
    from_slice!(hash, 32)

    // The code below not working by some reason:
    
    //      let mut sha = sha2::Sha256::new();
    //      sha.input(&type_id.to_le_bytes());
    //      sha.input(&workchain_id.to_le_bytes());
    //      sha.input(&shard.to_le_bytes());
    //      sha.input(from_slice!(file_hash, 32));    
    //      let buf = sha.result_reset();      
}
 
#[test] 
fn test_overlay_id() {
    let workchain_id : i32 = -1;
    let shard : i64 = -9223372036854775808;
    let file_hash = base64::decode("aAMjutqwMSgcejzVa/OWEHRiECI2i5yxn9FM/Thpa2Q=").unwrap();
    let file_hash = from_slice!(file_hash, 32);
    
    let full_id = calc_overlay_id(workchain_id, shard, &file_hash);
    assert_eq!(hex::encode(&full_id), "2441f387e2f355d4fd82ffc63d94d98e1d078d8855270a3d3c10c09e0701976f");
            
    let short_id = calc_overlay_short_id(full_id.to_vec());
    assert_eq!(hex::encode(&short_id), "dc7c6d60991db081780e7e12627d8c315dc171db982452e91f1f30d738cef966");
}

#[test]
fn test_address() {
    println!("----------------------------");
    let addr = "gSt1VYmndnZdNm+mIhobUFugKgINet+fvWkChlvp/I0=";
    let addr = base64::decode(addr).unwrap();
    let addr = from_slice!(addr, 32);
    let key = KeyOption::from_type_and_public_key(KeyOption::KEY_ED25519, &addr);
    println!("{}", base64::encode(key.id()));
    println!("{}", hex::encode(key.id()));
    
    let addr = "ccBetBO+46T/OZjPRlXkTdAIJD0Ca3KKEPReiB/cdX4=";
    let addr = base64::decode(addr).unwrap();
    let addr = from_slice!(addr, 32);
    let key = KeyOption::from_type_and_public_key(KeyOption::KEY_ED25519, &addr);
    println!("{}", base64::encode(key.id()));
    
    
    
    
    // let key = KeyOption::from_type_and_public_key(KeyOption::KEY_ED25519, &key.id());
    // println!("{}", base64::encode(key.id()));
    
    // let key = calc_overlay_short_id(addr.to_vec());
    // println!("{}", base64::encode(&key));
    
}


#[test] 
fn test_222() {
    let pkt = "bbcfe7f2ffffffff00000000000000800b1508003c8baa9199e26bbaef1f7b9116e3466cbfc49af38724601a1736fbcb175e25c8ba109bbcaabf4fcc8e75916d8e3c184d13ca6cf9a4494e7df7052a2b31f4cfa010000000";
    let pkt = &hex::decode(pkt).unwrap()[..];
    
        // Ok(GetNextKeyBlockIds { block: BlockIdExt { workchain: -1, shard: -9223372036854775808, 
        // seqno: 529675, root_hash: <3c8baa91... 32 bytes>, file_hash: <ba109bbc... 32 bytes> }, max_size: 16 })
    
    let pkt = deserialize(pkt).unwrap();
    let pkt = pkt.downcast::<GetNextKeyBlockIds>().unwrap();
    println!("{:?}", pkt);
    println!("file_hash: {:?}", hex::encode(pkt.block.file_hash.0));
    println!("root_hash: {:?}", hex::encode(pkt.block.root_hash.0));
    
    let fh = hex::decode("ba109bbcaabf4fcc8e75916d8e3c184d13ca6cf9a4494e7df7052a2b31f4cfa0").unwrap();
    let rh = hex::decode("3c8baa9199e26bbaef1f7b9116e3466cbfc49af38724601a1736fbcb175e25c8").unwrap();
    
    let qqq = ton_api::ton::tonNode::blockidext::BlockIdExt{
        workchain: -1, shard: -9223372036854775808, seqno: 529675,
        root_hash: ton_api::ton::int256(from_slice!(rh, 32)),
        file_hash: ton_api::ton::int256(from_slice!(fh, 32)),
    };
    let qqq = GetNextKeyBlockIds{ block: qqq, max_size: 16 };
    println!("{:?}", qqq);
        
    
}
