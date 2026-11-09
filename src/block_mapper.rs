/// Turns a 16 bit block number from a packet into a full block index. Block
/// numbers wrap at 65536, so this picks the index with that number closest to
/// `position`, the current place in the transfer.
pub fn block_index(block: u16, position: u64) -> u64 {
    // Read as signed, the wrapped difference is the shortest step from the
    // position to the block, forwards or backwards: 65535 becomes -1.
    let distance = block.wrapping_sub(position as u16) as i16;
    position
        .checked_add_signed(distance as i64)
        // There is nothing before index 0, so the block must be ahead instead.
        .unwrap_or(block as u64)
}

// cast keeps the low 16 bits = index % 65536
// 65535 = 1111111111111111
// 65535 = 1111111111111111
// 65536 = 10000000000000000
// 65536 = 0
// 65537 = 10000000000000001
// 65537 = 1
pub fn block_number(index: u64) -> u16 {
    index as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRAP: u64 = u16::MAX as u64 + 1;

    #[test]
    fn test_block_number_wraps_around() {
        // println!("{} = {:b}", WRAP - 1, WRAP - 1);
        // println!("{} = {:b}", WRAP - 1, block_number(WRAP - 1));
        // println!("{} = {:b}", WRAP, WRAP);
        // println!("{} = {:b}", WRAP, block_number(WRAP));
        // println!("{} = {:b}", WRAP + 1, WRAP + 1);
        // println!("{} = {:b}", WRAP + 1, block_number(WRAP + 1));
        assert_eq!(block_number(0), 0);
        assert_eq!(block_number(10000), 10000);
        assert_eq!(block_number(WRAP - 1), u16::MAX);
        assert_eq!(block_number(WRAP), 0);
        assert_eq!(block_number(WRAP + 2), 2);
        assert_eq!(block_number(2 * WRAP + 1998), 1998);
    }

    #[test]
    fn test_block_index_follows_the_transfer() {
        let cases = [
            (1, 0, 1),
            (2, 1, 2),
            (1, 1, 1),
            (0, 1, 0),
            (0, WRAP - 1, WRAP),
            (1, WRAP - 1, WRAP + 1),
            (u16::MAX, WRAP, WRAP - 1),
            (u16::MAX, WRAP + 3, WRAP - 1),
            (5, 3 * WRAP + 4, 3 * WRAP + 5),
            (u16::MAX, 3 * WRAP, 3 * WRAP - 1),
        ];
        for (block, position, expected) in cases {
            assert_eq!(block_index(block, position), expected, "{block} {position}");
        }
    }

    #[test]
    fn test_number_near_the_limit_early_in_a_transfer_is_not_the_previous_block() {
        assert_eq!(block_index(u16::MAX, WRAP), u16::MAX as u64);
        assert_eq!(block_index(0, WRAP + 1), WRAP);
        assert_eq!(block_index(u16::MAX, 1), u16::MAX as u64);
        assert_eq!(block_index(55536, 1), 55536);
    }
}
