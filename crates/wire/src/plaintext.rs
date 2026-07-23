use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextDataClassKind {
    MessageContent,
    StrandContent,
    AttachmentPlaintext,
    AttachmentPreview,
    Thumbnail,
    FullTextIndex,
    SearchSnippet,
    Embedding,
    NotificationSummary,
    InboxPreview,
    HistoryPreview,
    PublicHistoryExport,
    MediaPlaintext,
    DerivedPlaintext,
    AccountPrivateState,
    ProfilePrivateField,
}
