#[macro_export]
macro_rules! to_sql_methods {
    ($t:ty) => {
        fn to_sql(
            &self,
            ty: &$crate::postgres::types::Type,
            out: &mut Vec<u8>,
        ) -> Result<$crate::postgres::types::IsNull, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            self.0.to_sql(ty, out)
        }

        fn accepts(ty: &$crate::postgres::types::Type) -> bool {
            <$t>::accepts(ty)
        }

        fn to_sql_checked(
            &self,
            ty: &$crate::postgres::types::Type,
            out: &mut Vec<u8>,
        ) -> Result<$crate::postgres::types::IsNull, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            self.0.to_sql_checked(ty, out)
        }
    };
}

#[macro_export]
macro_rules! from_sql_methods {
    ($t:ty) => {
        fn from_sql(
            ty: &$crate::postgres::types::Type,
            raw: &[u8],
        ) -> Result<Self, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            <$t>::from_sql(ty, raw).map(|x| Self{0: x})
        }

        fn accepts(ty: &$crate::postgres::types::Type) -> bool {
            <$t>::accepts(ty)
        }

        fn from_sql_null(
            ty: &$crate::postgres::types::Type,
        ) -> Result<Self, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            <$t>::from_sql_null(ty).map(|x| Self{0: x})
        }

        fn from_sql_nullable(
            ty: &$crate::postgres::types::Type,
            raw: Option<&[u8]>,
        ) -> Result<Self, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            <$t>::from_sql_nullable(ty, raw).map(|x| Self{0: x})
        }
    };
}

#[macro_export]
macro_rules! cow_to_sql_methods {
    ($t:ty) => {
        fn to_sql(
            &self,
            ty: &$crate::postgres::types::Type,
            out: &mut Vec<u8>,
        ) -> Result<$crate::postgres::types::IsNull, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            self.0.as_ref().to_sql(ty, out)
        }

        fn accepts(ty: &$crate::postgres::types::Type) -> bool {
            <$t>::accepts(ty)
        }

        fn to_sql_checked(
            &self,
            ty: &$crate::postgres::types::Type,
            out: &mut Vec<u8>,
        ) -> Result<$crate::postgres::types::IsNull, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            self.0.as_ref().to_sql_checked(ty, out)
        }
    };
}

#[macro_export]
macro_rules! cow_from_sql_methods {
    ($t:ty) => {
        fn from_sql(
            ty: &$crate::postgres::types::Type,
            raw: &[u8],
        ) -> Result<Self, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            <$t as ToOwned>::Owned::from_sql(ty, raw)
                .map(|x| Self{0: Cow::Owned(x)})
        }

        fn accepts(ty: &$crate::postgres::types::Type) -> bool {
            <$t as ToOwned>::Owned::accepts(ty)
        }

        fn from_sql_null(
            ty: &$crate::postgres::types::Type,
        ) -> Result<Self, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            <$t as ToOwned>::Owned::from_sql_null(ty)
                .map(|x| Self{0: Cow::Owned(x)})
        }

        fn from_sql_nullable(
            ty: &$crate::postgres::types::Type,
            raw: Option<&[u8]>,
        ) -> Result<Self, Box<$crate::std::error::Error + 'static + Sync + Send>> {
            <$t as ToOwned>::Owned::from_sql_nullable(ty, raw)
                .map(|x| Self{0: Cow::Owned(x)})
        }
    };
}
