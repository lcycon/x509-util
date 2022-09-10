use bumpalo_herd::Herd;

#[derive(Default)]
pub struct Context {
    herd: Herd,
}

impl Context {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_reference(&self, data: &[u8]) -> &[u8] {
        self.herd.get().alloc_slice_copy(data)
    }
}

pub trait Alloc {
    fn alloc_into(self, context: &Context) -> &[u8];
}

impl<T: AsRef<[u8]>> Alloc for T {
    fn alloc_into(self, context: &Context) -> &[u8] {
        context.with_reference(self.as_ref())
    }
}
