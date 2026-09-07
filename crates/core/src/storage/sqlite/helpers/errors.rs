//! The one mapping from the driver's errors to [`StoreError`].
//!
//! Every SQLite store method ends with `.map_err(map_store_error)`, so a
//! constraint the database rejects surfaces as `Conflict` and a missing row
//! as `NotFound` from every method alike. Nothing else in the backend
//! inspects a `rusqlite::Error`.

use crate::error::StoreError;

/// Extended result codes that mean "the row collides with one that exists
/// or refers to one that does not", which a caller can act on. A NOT NULL
/// or CHECK failure is a bug in the caller and stays `Database`.
const CONFLICT_CODES: [i32; 3] = [
    rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
    rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY,
    rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
];

/// Map a driver error. The conflict message is SQLite's own, which names
/// the constraint when it knows it (`UNIQUE constraint failed:
/// users.username`); a foreign-key failure carries no name.
pub(crate) fn map_rusqlite_error(e: rusqlite::Error) -> StoreError {
    match e {
        rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound("row not found".to_string()),
        rusqlite::Error::SqliteFailure(code, message)
            if CONFLICT_CODES.contains(&code.extended_code) =>
        {
            StoreError::Conflict {
                message: message.unwrap_or_else(|| code.to_string()),
                existing_id: None,
            }
        }
        other => StoreError::Database(other.to_string()),
    }
}

/// Map the error a `Connection::call` closure returns. A `StoreError` the
/// closure raised itself (through [`store_err_to_tokio`]) comes back as it
/// was; a driver error goes through [`map_rusqlite_error`].
///
/// [`store_err_to_tokio`]: super::store_err_to_tokio
pub(crate) fn map_store_error(e: tokio_rusqlite::Error) -> StoreError {
    match e {
        tokio_rusqlite::Error::Rusqlite(inner) => map_rusqlite_error(inner),
        tokio_rusqlite::Error::Other(boxed) => match boxed.downcast::<StoreError>() {
            Ok(store_err) => *store_err,
            Err(other) => StoreError::Database(other.to_string()),
        },
        other => StoreError::Database(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraint(extended_code: i32, message: &str) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                extended_code,
            },
            Some(message.to_string()),
        )
    }

    #[test]
    fn unique_primary_key_and_foreign_key_failures_are_conflicts() {
        for (code, message) in [
            (
                rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
                "UNIQUE constraint failed: users.username",
            ),
            (
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY,
                "UNIQUE constraint failed: credentials.id",
            ),
            (
                rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
                "FOREIGN KEY constraint failed",
            ),
        ] {
            match map_rusqlite_error(constraint(code, message)) {
                StoreError::Conflict { message: got, .. } => assert_eq!(got, message),
                other => panic!("{message}: expected Conflict, got {other:?}"),
            }
        }
    }

    #[test]
    fn not_null_and_check_failures_stay_database_errors() {
        for code in [
            rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL,
            rusqlite::ffi::SQLITE_CONSTRAINT_CHECK,
        ] {
            assert!(matches!(
                map_rusqlite_error(constraint(code, "x")),
                StoreError::Database(_)
            ));
        }
    }

    #[test]
    fn no_rows_is_not_found() {
        assert!(matches!(
            map_rusqlite_error(rusqlite::Error::QueryReturnedNoRows),
            StoreError::NotFound(_)
        ));
    }

    #[test]
    fn a_store_error_raised_inside_a_call_comes_back_unchanged() {
        let raised = super::super::store_err_to_tokio(StoreError::NotFound("user x".into()));
        assert!(matches!(map_store_error(raised), StoreError::NotFound(m) if m == "user x"));
    }
}
