#![allow(dead_code)]

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "config_revisions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub revision: i64,
    pub content_hash: String,
    pub source_node: String,
    pub committed_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "resource_document::Entity")]
    ResourceDocument,
}

impl Related<resource_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ResourceDocument.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

pub mod resource_document {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "resource_documents")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub resource_type: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub resource_name: String,
        pub revision: i64,
        pub payload: String,
        pub updated_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::Entity",
            from = "Column::Revision",
            to = "super::Column::Revision"
        )]
        ConfigRevision,
    }

    impl Related<super::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::ConfigRevision.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}
