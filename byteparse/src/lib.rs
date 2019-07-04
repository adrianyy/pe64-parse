pub use byteparse_derive::*;
use std::io::{self, Read};

/// A type which can be directly created from byte buffer.
/// Must be primitive, cannot have any padding. Conversion is memcpy-like.
pub unsafe trait Bytecopy: Copy {
    /// Read bytes from `r` and copy them to `self`.
    fn copy_to<R: Read>(&mut self, r: &mut R) -> io::Result<()>;
}

/// Implement Bytecopy trait for primitives.
macro_rules! impl_bc {
    ($( $type:tt ),*) => {
        $( unsafe impl Bytecopy for $type {
            fn copy_to<R: Read>(&mut self, r: &mut R) -> io::Result<()> {
                use std::convert::TryInto;

                // Largest primitive is (u/i)128 which has 16 bytes.
                let mut buf = [0u8; 16];
                let len     = std::mem::size_of::<Self>();

                // Ensure type can fit in buf.
                assert!(len <= 16, "Type is too big ({}).", len);

                // Read sizeof(Self) bytes.
                r.read_exact(&mut buf[..len])?;

                // Try converting &[u8] to [u8; sizeof(Self)]. Should
                // never fail.
                let buf = (&buf[..len]).try_into()
                    .expect("Read whole buffer but converting failed.");

                // Copy primitive to `self`.
                *self = Self::from_le_bytes(buf);
                
                Ok(())
            }
        } )*
    }
}

// All primitive types are Bytecopy.
impl_bc!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);

/// A type which can be created from byte buffer.
/// Its members must be Byteparse. Conversion is memcpy-like for
/// primitives and more compilcated for other types. 
pub unsafe trait Byteparse: Copy {
    /// Parse bytes read from `r` and copy parsed structure to `self`.
    fn parse_to<R: Read>(&mut self, r: &mut R) -> io::Result<()>;

    /// Parse bytes read from `r` and return newly parsed structure.
    fn parse<R: Read>(r: &mut R) -> io::Result<Self>
        where Self: Default
    {
        // Create default instance and parse data into it.
        let mut s = Self::default();
        s.parse_to(r)?;

        Ok(s)
    }
}

// Byteparse for primitives is simple memcpy. Implement Byteparse
// for all primitives that are Bytecopy.
unsafe impl<T: Bytecopy> Byteparse for T {
    fn parse_to<R: Read>(&mut self, r: &mut R) -> io::Result<()> {
        // Just copy the bytes.
        self.copy_to(r)
    }
}

/// Helper trait that allows writing
/// ```reader.parse()```
/// instead of
/// ```Value::parse(&mut reader)```
pub trait ByteparseHelper<T, U> {
    /// Parse bytes read from `self` and return newly parsed structure.
    fn parse(&mut self) -> io::Result<T>;
}

// Implement ByteparseHelper for all Byteparse and Default types.
// Parsed type must be Default because we need to create default instance of it
// in `Byteparse::parse` function.
impl<T, U> ByteparseHelper<T, U> for U
    where T: Byteparse + Default, U: Read
{
    fn parse(&mut self) -> io::Result<T> {
        // Just call Byteparse implementation.
        T::parse(self)
    }
}

/// Implement Byteparse for array of `n` Byteparse elements.
macro_rules! impl_bp_a1 {
    ($( $n:expr ),*) => {
        $( unsafe impl<T: Byteparse> Byteparse for [T; $n] {
            fn parse_to<R: Read>(&mut self, r: &mut R) -> io::Result<()> {
                // Try to parse each element at once.
                for v in self.iter_mut() {
                    v.parse_to(r)?;
                }
                
                Ok(())
            }
        } )*
    }
}

/// As above, for [n, n + 10) elements.
macro_rules! impl_bp_a10 {
    ($( $n:expr ),*) => {
        $( impl_bp_a1!($n, $n+1, $n+2, $n+3, $n+4,
            $n+5, $n+6, $n+7, $n+8, $n+9); )*
    }
}

/// As above, for [n, n + 100) elements.
macro_rules! impl_bp_a100 {
    ($( $e:expr ),*) => {
        $( impl_bp_a10!($e, $e+10, $e+20, $e+30, $e+40,
            $e+50, $e+60, $e+70, $e+80, $e+90); )*
    }
}

// Implement Byteparse for arrays of Byteparse types.
// Currently size limit is 500 elements.
impl_bp_a100!(0, 100, 200, 300, 400);