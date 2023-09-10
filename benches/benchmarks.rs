#![feature(test)]
extern crate test;

use std::collections::BTreeMap;

use rand::Rng;
use test::Bencher;
use tftp::config::MAX_BUFFER_SIZE;

#[bench]
fn test_packet_to_bytes_with_iter(b: &mut Bencher) {
    b.iter(|| {
        let random_bytes: Vec<u8> = (0..MAX_BUFFER_SIZE - 4)
            .map(|_| rand::random::<u8>())
            .collect();
        let data_packet: Vec<u8> = 1_u16
            .to_be_bytes()
            .into_iter()
            .chain(random_bytes.into_iter())
            .collect();
        let _packet: Vec<u8> = 5_u16
            .to_be_bytes()
            .into_iter()
            .chain(data_packet.into_iter())
            .collect();
    });
}

#[bench]
fn test_packet_to_bytes_with_concat(b: &mut Bencher) {
    b.iter(|| {
        let random_bytes: Vec<u8> = (0..MAX_BUFFER_SIZE - 4)
            .map(|_| rand::random::<u8>())
            .collect();
        let data_packet: Vec<u8> = [1_u16.to_be_bytes().to_vec(), random_bytes].concat();
        let _packet: Vec<u8> = [5_u16.to_be_bytes().to_vec(), data_packet].concat();
    });
}

#[bench]
fn test_packet_to_bytes_with_extend(b: &mut Bencher) {
    b.iter(|| {
        let random_bytes: Vec<u8> = (0..MAX_BUFFER_SIZE - 4)
            .map(|_| rand::random::<u8>())
            .collect();
        let mut data_packet: Vec<u8> = 1_u16.to_be_bytes().to_vec();
        data_packet.extend(random_bytes);
        let mut packet: Vec<u8> = 5_u16.to_be_bytes().to_vec();
        packet.extend(data_packet);
    });
}

#[bench]
fn test_vector_resizing(b: &mut Bencher) {
    let mut vec: Vec<u8> = Vec::new();
    vec.resize(MAX_BUFFER_SIZE as usize, 0);
    b.iter(|| {
        vec.resize(MAX_BUFFER_SIZE as usize, 0);
        vec.truncate(rand::random::<u8>() as usize);
    });
}

// TODO slow
#[bench]
fn test_heapless_vector_resizing(b: &mut Bencher) {
    let mut vec: heapless::Vec<u8, { MAX_BUFFER_SIZE as usize }> = heapless::Vec::new();
    vec.resize(MAX_BUFFER_SIZE as usize, 0).unwrap();
    b.iter(|| {
        vec.resize(MAX_BUFFER_SIZE as usize, 0).unwrap();
        vec.truncate(rand::random::<u8>() as usize);
    });
}

#[bench]
fn test_heapless_vector_set_len(b: &mut Bencher) {
    let mut vec: heapless::Vec<u8, { MAX_BUFFER_SIZE as usize }> = heapless::Vec::new();
    vec.resize(MAX_BUFFER_SIZE as usize, 0).unwrap();
    b.iter(|| {
        unsafe { vec.set_len(MAX_BUFFER_SIZE as usize) };
        vec.truncate(rand::random::<u8>() as usize);
    });
}

#[bench]
fn test_array_vector_resizing(b: &mut Bencher) {
    let mut vec: arrayvec::ArrayVec<u8, { MAX_BUFFER_SIZE as usize }> = arrayvec::ArrayVec::new();
    // no resize
    unsafe { vec.set_len(MAX_BUFFER_SIZE as usize) };
    b.iter(|| {
        unsafe { vec.set_len(MAX_BUFFER_SIZE as usize) };
        vec.truncate(rand::random::<u8>() as usize);
    });
}

#[bench]
fn test_btree_retrieve_256(b: &mut Bencher) {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i <= u8::MAX {
        map.insert(i, true);

        if i == u8::MAX {
            break;
        }
        i += 1;
    }

    b.iter(|| {
        map.get(&rand::random::<u8>()).unwrap();
    });
}

#[bench]
fn test_heapless_map_retrieve_256(b: &mut Bencher) {
    let mut map = heapless::FnvIndexMap::<u8, bool, { u8::MAX as usize + 1 }>::new();
    let mut i = 0;
    while i <= u8::MAX {
        map.insert(i, true);

        if i == u8::MAX {
            break;
        }
        i += 1;
    }

    b.iter(|| {
        map.get(&rand::random::<u8>()).unwrap();
    });
}

#[bench]
fn test_arrayvec_retrieve_256(b: &mut Bencher) {
    let mut map = arrayvec::ArrayVec::<u8, { u8::MAX as usize + 1 }>::new();
    let mut i = 0;
    while i <= u8::MAX {
        map.push(i);
        if i == u8::MAX {
            break;
        }
        i += 1;
    }

    b.iter(|| {
        let random_index = rand::random::<u8>();
        map.iter().find(|i| *i == &random_index).unwrap();
    });
}

#[bench]
fn test_btree_retrieve_20(b: &mut Bencher) {
    const SIZE: usize = 20;
    let mut map = BTreeMap::new();
    let mut i: u8 = 0;
    while i as usize <= SIZE {
        map.insert(i, true);
        if i as usize == SIZE - 1 {
            break;
        }
        i += 1;
    }
    let mut rng = rand::thread_rng();
    b.iter(|| {
        let random_index = rng.gen_range(0..19);
        map.get(&random_index).unwrap();
    });
}

#[bench]
fn test_heapless_map_retrieve_20(b: &mut Bencher) {
    const SIZE: usize = 20;
    let mut map = heapless::FnvIndexMap::<u8, bool, { u8::MAX as usize + 1 }>::new();
    let mut i: u8 = 0;
    while i as usize <= SIZE {
        map.insert(i, true).unwrap();
        if i as usize == SIZE - 1 {
            break;
        }
        i += 1;
    }
    let mut rng = rand::thread_rng();
    b.iter(|| {
        let random_index = rng.gen_range(0..19);
        map.get(&random_index).unwrap();
    });
}

#[bench]
fn test_arrayvec_retrieve_20(b: &mut Bencher) {
    const SIZE: usize = 20;
    let mut map = arrayvec::ArrayVec::<u8, { SIZE }>::new();
    let mut i: u8 = 0;
    while i as usize <= SIZE {
        map.push(i);
        if i as usize == SIZE - 1 {
            break;
        }
        i += 1;
    }
    let mut rng = rand::thread_rng();
    b.iter(|| {
        let random_index = rng.gen_range(0..19);
        map.iter().find(|i| *i == &random_index).unwrap();
    });
}

#[cfg(feature = "encryption")]
#[bench]
fn test_encrypt_decrypt(b: &mut Bencher) {
    use tftp::config::MAX_DATA_BLOCK_SIZE;
    use tftp::types::DataBuffer;

    let encryptor = create_encryptor();
    let mut rng = rand::thread_rng();
    let mut blocks = Vec::new();
    for _ in 0..1000 {
        let bytes: Vec<u8> = (0..MAX_DATA_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
        let data: DataBuffer = bytes.into_iter().collect();
        blocks.push(data);
    }

    b.iter(|| {
        let random_index = rng.gen_range(0..blocks.len() - 1);
        encryptor.encrypt(&mut blocks[random_index]).unwrap();
        encryptor.decrypt(&mut blocks[random_index]).unwrap();
    });
}

#[cfg(feature = "encryption")]
fn create_encryptor() -> tftp::encryption::Encryptor {
    use chacha20poly1305::KeyInit;
    use chacha20poly1305::XChaCha20Poly1305;
    tftp::encryption::Encryptor {
        cipher: XChaCha20Poly1305::new(
            &[
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ]
            .into(),
        ),
        nonce: [
            1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99,
        ]
        .into(),
    }
}
