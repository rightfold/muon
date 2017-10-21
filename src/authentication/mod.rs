use std::borrow::Cow;
use std::fmt;

use postgres as postgres_;
use ring::digest;
use ring::pbkdf2;
use uuid::Uuid;

static PBKDF2_DIGEST_ALGORITHM: &'static digest::Algorithm = &digest::SHA256;

/// A user identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UserId(pub Uuid);

impl postgres_::types::ToSql for UserId { to_sql_methods!(Uuid); }
impl postgres_::types::FromSql for UserId { from_sql_methods!(Uuid); }

/// A username.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Username<'a>(pub Cow<'a, str>);

impl<'a> From<&'a str> for Username<'a> {
    fn from(other: &'a str) -> Self {
        Username(Cow::from(other))
    }
}

impl<'a> postgres_::types::ToSql for Username<'a> { cow_to_sql_methods!(&'a str); }
impl<'a> postgres_::types::FromSql for Username<'a> { cow_from_sql_methods!(str); }

/// A password.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Password<'a>(pub &'a str);

impl<'a> postgres_::types::ToSql for Password<'a> { to_sql_methods!(&'a str); }

impl<'a> fmt::Debug for Password<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        "********".fmt(f)
    }
}

/// A password salt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordSalt<'a>(pub Cow<'a, [u8]>);

impl<'a> postgres_::types::ToSql for PasswordSalt<'a> { cow_to_sql_methods!(&'a [u8]); }
impl<'a> postgres_::types::FromSql for PasswordSalt<'a> { cow_from_sql_methods!([u8]); }

/// A password hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordHash<'a>(pub Cow<'a, [u8]>);

impl<'a> postgres_::types::ToSql for PasswordHash<'a> { cow_to_sql_methods!(&'a [u8]); }
impl<'a> postgres_::types::FromSql for PasswordHash<'a> { cow_from_sql_methods!([u8]); }

/// A user, as far as authentication is concerned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User<'a> {
    user_id: UserId,
    password_iterations: u32,
    password_salt: PasswordSalt<'a>,
    password_hash: PasswordHash<'a>,
}

/// A response to an authentication challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response<'a> {
    pub username: Username<'a>,
    pub password: Password<'a>,
}

/// Find a user and check the password against theirs.
pub fn authenticate<A>(user_finder: &A, response: &Response) -> Result<Option<UserId>, A::Error>
    where A: UserFinder {
    user_finder.find_user(&response.username).map(|user| {
        user.iter()
            .filter(|user| check_password(&user, &response.password))
            .map(|user| user.user_id)
            .next()
    })
}

fn check_password(user: &User, password: &Password) -> bool {
    pbkdf2::verify(
        PBKDF2_DIGEST_ALGORITHM,
        user.password_iterations,
        user.password_salt.0.as_ref(),
        password.0.as_bytes(),
        user.password_hash.0.as_ref(),
    ).is_ok()
}

/// Something that can find a user by username.
pub trait UserFinder {
    type Error;

    fn find_user(&self, &Username) -> Result<Option<User>, Self::Error>;
}

pub mod hash_map;
pub mod postgres;

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    fn make_user(password: &Password) -> User<'static> {
        let password_iterations = 4;
        let password_salt = &[0x01, 0x02, 0x03, 0x04];
        let mut password_hash = vec![0; 32];
        pbkdf2::derive(
            PBKDF2_DIGEST_ALGORITHM,
            password_iterations,
            password_salt.as_ref(),
            password.0.as_bytes(),
            &mut password_hash,
        );
        User{
            user_id: UserId(Uuid::new_v4()),
            password_iterations,
            password_salt: PasswordSalt(Cow::Borrowed(password_salt)),
            password_hash: PasswordHash(Cow::Owned(password_hash)),
        }
    }

    #[test]
    fn test_authenticate() {
        let cases = [
            /* username , actual    , attempt   , exists */
            (  "steve"  , "hunter2" , "hunter2" , true    ),
            (  "jack"   , "foobar1" , "hunter2" , true    ),
            (  "mary"   , "mary"    , "mary"    , true    ),
            (  "rob"    , "rob"     , "mary"    , true    ),
            (  "god"    , ""        , "jesus"   , false   ),
        ];

        let mut users = HashMap::new();
        for &(username, actual, _attempt, exists) in cases.iter() {
            if exists {
                let user = make_user(&Password(actual));
                users.insert(username, user);
            }
        }
        let user_finder = hash_map::HashMapUserFinder(users.clone());

        for &(username, actual, attempt, exists) in cases.iter() {
            let response = Response{
                username: Username::from(username),
                password: Password(attempt),
            };
            let result = authenticate(&user_finder, &response).unwrap();
            if exists && actual == attempt {
                assert_eq!(Some(users[username].user_id), result);
            } else {
                assert_eq!(result, None);
            }
        }
    }
}
