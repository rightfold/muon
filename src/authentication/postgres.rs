use postgres;

use authentication::{User, UserFinder, Username};

/// Find users by username in a database.
#[derive(Debug)]
pub struct PostgresUserFinder<'a> {
    statement: postgres::stmt::Statement<'a>,
}

impl<'a> PostgresUserFinder<'a> {
    pub fn new(connection: &'a postgres::Connection) -> Result<Self, postgres::Error> {
        let statement = connection.prepare("
            SELECT id, password_iterations, password_salt, password_hash
            FROM users
            WHERE username = $1
        ")?;
        Ok(PostgresUserFinder{statement})
    }
}

impl<'a> UserFinder for PostgresUserFinder<'a> {
    type Error = postgres::Error;

    fn find_user(&self, username: &Username) -> Result<Option<User>, postgres::Error> {
        match self.statement.query(&[username])?.iter().next() {
            None => Ok(None),
            Some(row) => {
                let user = User{
                    user_id: row.get(0),
                    password_iterations: row.get(1),
                    password_salt: row.get(2),
                    password_hash: row.get(3),
                };
                Ok(Some(user))
            },
        }
    }
}
