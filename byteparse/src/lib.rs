pub use byteparse_derive::*;
use std::io::{self, Read};

pub unsafe trait Bytecopy: Copy {
    fn copy_to<R: Read>(&mut self, r: &mut R) -> io::Result<()> {
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                self as *mut _ as *mut u8,
                std::mem::size_of::<Self>()
            )
        };

        r.read_exact(buf)?;
        Ok(())
    }
}

macro_rules! impl_bc {
    ($( $t:tt ),*) => {
        $( unsafe impl Bytecopy for $t {} )*
    }
}

impl_bc!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);

pub unsafe trait Byteparse: Copy {
    fn parse_to<R: Read>(&mut self, r: &mut R) -> io::Result<()>;
    fn parse<R: Read>(r: &mut R) -> io::Result<Self>
        where Self: Default
    {
        let mut s: Self = Default::default();
        s.parse_to(r)?;

        Ok(s)
    }
}

unsafe impl<T: Bytecopy> Byteparse for T {
    fn parse_to<R: Read>(&mut self, r: &mut R) -> io::Result<()> {
        self.copy_to(r)
    }
}

pub trait ByteparseHelper<T, U> {
    fn parse(&mut self) -> io::Result<T>;
}

impl<T, U> ByteparseHelper<T, U> for U
    where T: Byteparse + Default, U: Read
{
    fn parse(&mut self) -> io::Result<T> {
        T::parse(self)
    }
}

macro_rules! impl_bp_a1 {
    ($( $e:expr ),*) => {
        $( unsafe impl<T: Byteparse> Byteparse for [T; $e] {
			fn parse_to<R: Read>(&mut self, r: &mut R) -> io::Result<()> {
				for i in 0..$e {
					self[i].parse_to(r)?;
				}
				
				Ok(())
			}
		} )*
    }
}

macro_rules! impl_bp_a10 {
    ($( $e:expr ),*) => {
        $( impl_bp_a1!($e, $e+1, $e+2, $e+3, $e+4,
            $e+5, $e+6, $e+7, $e+8, $e+9); )*
    }
}

macro_rules! impl_bp_a100 {
    ($( $e:expr ),*) => {
        $( impl_bp_a10!($e, $e+10, $e+20, $e+30, $e+40,
            $e+50, $e+60, $e+70, $e+80, $e+90); )*
    }
}

impl_bp_a100!(0, 100, 200, 300, 400, 500);
