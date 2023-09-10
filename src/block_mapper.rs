#[derive(Debug, Clone, Copy)]
pub struct BlockMapper {
    current_block_set: u64,
    next_block_set: u64,
}

impl BlockMapper {
    pub fn new() -> Self {
        Self {
            current_block_set: 1,
            next_block_set: 1,
        }
    }

    pub fn index(&mut self, block: u16) -> u64 {
        if self.current_block_set == self.next_block_set && block > u16::MAX - 10000 {
            self.next_block_set += 1;
        }
        if self.current_block_set != self.next_block_set {
            if block < 10000 {
                let next_block = self.next_block_set - 1;
                return (next_block * u16::MAX as u64) + block as u64 + next_block;
            } else if (10000..20000).contains(&block) {
                self.current_block_set += 1;
            }
        }
        let current_block = self.current_block_set - 1;
        let mut index = (current_block * u16::MAX as u64) + block as u64;
        if current_block > 0 {
            index += current_block;
        }
        index
    }

    // block index
    // 0 0
    // 1 1
    // 2 2
    // 3 3
    // 4 4
    // 5 5
    // 0 6
    // 1 7
    // 2 8
    // 3 9
    // 4 10
    // 5 11
    // 0 12
    // 1 13
    // 2 14
    // 3 15
    // 4 16
    // 5 17
    // 0 18
    // 1 19
    // 2 20
    // 3 21
    pub fn block(&self, index: u64) -> u16 {
        if index > u16::MAX as u64 {
            let part = index / (u16::MAX as u64 + 1);
            return (index - (part * (u16::MAX as u64 + 1))) as u16;
        }
        index as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_mapper() {
        let mut mapper = BlockMapper::new();
        assert_eq!(0, mapper.block(0));
        assert_eq!(10000, mapper.block(10000));
        assert_eq!(0, mapper.index(0));
        assert_eq!(10000, mapper.index(10000));
        // rollover to next part start
        assert_eq!(u16::MAX as u64, mapper.index(u16::MAX));
        assert_eq!((u16::MAX - 2) as u64, mapper.index(u16::MAX - 2));
        assert_eq!(u16::MAX as u64 + 1, mapper.index(0));
        assert_eq!(u16::MAX as u64 + 3, mapper.index(2));

        assert_eq!(2, mapper.block(2));
        assert_eq!(u16::MAX, mapper.block(u16::MAX as u64));
        assert_eq!(0, mapper.block(u16::MAX as u64 + 1));

        // rollover finished
        assert_eq!(u16::MAX as u64 + 10001, mapper.index(10000));
        assert_eq!(u16::MAX as u64 + 10002, mapper.index(10001));
        assert_eq!(9999, mapper.block(u16::MAX as u64 + 10000));

        // rollover to next part start
        assert_eq!(
            u16::MAX as u64 + u16::MAX as u64 - 9998,
            mapper.index(u16::MAX - 9999)
        );

        assert_eq!(2 * (u16::MAX as u64) + 2, mapper.index(0));
        assert_eq!(2 * (u16::MAX as u64) + 3, mapper.index(1));

        assert_eq!(65534, mapper.block(2 * (u16::MAX as u64)));
        assert_eq!(65535, mapper.block(2 * (u16::MAX as u64) + 1));
        assert_eq!(0, mapper.block(2 * (u16::MAX as u64) + 2));
        assert_eq!(1998, mapper.block(2 * (u16::MAX as u64) + 2000));
        assert_eq!(9997, mapper.block(2 * (u16::MAX as u64) + 9999));
    }
}
