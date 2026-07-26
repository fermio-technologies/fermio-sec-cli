use fermio_core::SourceLocation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramIr {
    pub modules: Vec<ModuleIr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIr {
    pub language: String,
    pub path: String,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Instruction {
    Call {
        target: String,
        arguments: Vec<String>,
        location: SourceLocation,
    },
    Assignment {
        target: String,
        value: String,
        location: SourceLocation,
    },
    Literal {
        value: String,
        location: SourceLocation,
    },
}
