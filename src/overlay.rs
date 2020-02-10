extern crate hex;

use adnl::{
    common::{
        AdnlResult, Query, QueryResult, Subscriber, 
    }, 
    node::{
        AdnlNode, AdnlNodeAddress
    }
};
use std::{sync::Arc};
use ton_api::ton::{
    TLObject, 
    rpc::tonNode::{
            GetNextKeyBlockIds, DownloadBlockFull, 
        },
    overlay::Nodes as OverlayNodes,
    overlay::node::Node as OverlayNode,
    rpc::overlay::{
        GetRandomPeers,
    },
    tonNode::{
        blockidext::BlockIdExt, KeyBlocks,
    },
};

/// Overlay Node
pub struct Overlay {
    adnl: Arc<AdnlNode>,
}

impl Overlay {

    /// Constructor 
    pub fn with_adnl_node(adnl: Arc<AdnlNode>) -> AdnlResult<Arc<Self>> {
        let ret = Self { adnl };
        Ok(Arc::new(ret))
    }
    
    fn create_prefix() -> Vec<u8> {
        // TODO: hard-coded prefix!
        let pfx = hex::decode("4384fdccdc7c6d60991db081780e7e12627d8c315dc171db982452e91f1f30d738cef966").unwrap();
        pfx
    }

    /// overlay.GetRandomPeers
    pub async fn get_random_peers(&self, dst: &AdnlNodeAddress) -> AdnlResult<Vec<OverlayNode>> {
        let peers = ton_api::ton::overlay::nodes::Nodes::default();
        let query = TLObject::new(GetRandomPeers{peers});
        let answer = self.adnl.query_with_prefix(
            dst, 
            Some(Overlay::create_prefix().as_slice()), 
            &query
        ).await?;
        let answer: OverlayNodes = Query::parse(answer, &query)?;
        let answer = answer.only().nodes.0;
        Ok(answer)    
    }
                    
    /// GetNextKeyBlockIds
    pub async fn get_next_block_ids(&self, block_id : BlockIdExt, max_size : i32, dst: &AdnlNodeAddress) -> AdnlResult<Vec<BlockIdExt>> {
    
        let query = GetNextKeyBlockIds{ block: block_id, max_size };
        let query = TLObject::new(query);
        let answer = self.adnl.query_with_prefix(
            dst, 
            Some(Overlay::create_prefix().as_slice()), 
            &query
        ).await?;
        let answer: KeyBlocks = Query::parse(answer, &query)?;
        // println!("{:?}", answer);
        let answer = answer.only().blocks.0;
        Ok(answer)    
    }
                    
    /// DownloadBlock
    pub async fn download_block(&self, block_id : BlockIdExt, dst: &AdnlNodeAddress) -> AdnlResult<Vec<BlockIdExt>> {
    
        let query = DownloadBlockFull { block: block_id };
        let query = TLObject::new(query);
        let answer = self.adnl.query_with_prefix(
            dst, 
            Some(Overlay::create_prefix().as_slice()), 
            &query
        ).await?;
        println!("{:?}", answer);
        let answer: KeyBlocks = Query::parse(answer, &query)?;
        let answer = answer.only().blocks.0;
        Ok(answer)    
    }

/*                    
    fn node_key(&self) -> AdnlResult<&Arc<KeyOption>> {
        self.adnl.key(self.node_key_index)
    }  
*/

}

impl Subscriber for Overlay {

    fn try_consume_query(&self, object: TLObject) -> AdnlResult<QueryResult> {
        Ok(QueryResult::Rejected(object))
    }    
/*
    fn try_consume_query_bundle(&self, mut objects: Vec<TLObject>) -> AdnlResult<QueryResult> {
    }    
*/
}


