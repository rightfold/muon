use std::collections::HashMap;

use authentication::{User, UserFinder, Username};

/// Find users by username in a hash map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashMapUserFinder<'a, 'b>(pub HashMap<&'a str, User<'b>>);

impl<'a, 'b> HashMapUserFinder<'a, 'b> {
    pub fn new() -> Self {
        HashMapUserFinder(HashMap::new())
    }
}

impl<'a, 'b> UserFinder for HashMapUserFinder<'a, 'b> {
    type Error = !;

    fn find_user(&self, username: &Username) -> Result<Option<User>, !> {
        Ok(self.0.get(username.0.as_ref()).map(Clone::clone))
    }
}
