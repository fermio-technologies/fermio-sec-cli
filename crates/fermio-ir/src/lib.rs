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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValueId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum LiteralValue {
    String(String),
    Integer(String),
    Float(String),
    Boolean(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Function,
    Method,
    NullsafeMethod,
    StaticMethod,
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Instruction {
    VariableRead {
        output: ValueId,
        name: String,
        location: SourceLocation,
    },
    Literal {
        output: ValueId,
        value: LiteralValue,
        location: SourceLocation,
    },
    Assignment {
        target: String,
        value: ValueId,
        location: SourceLocation,
    },
    Concatenate {
        output: ValueId,
        operands: Vec<ValueId>,
        location: SourceLocation,
    },
    Call {
        output: ValueId,
        target: String,
        call_kind: CallKind,
        arguments: Vec<ValueId>,
        location: SourceLocation,
    },
    Return {
        value: Option<ValueId>,
        location: SourceLocation,
    },
    Opaque {
        output: ValueId,
        expression: String,
        location: SourceLocation,
    },
}
