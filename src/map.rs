use arrayvec::ArrayVec;

/// Simple map which relies on the fact that there wont be many entries see benches
#[derive(Clone, Debug)]
pub struct Map<K, V, const CAP: usize> {
    array: ArrayVec<(K, V), CAP>,
}

impl<K, V, const CAP: usize> Default for Map<K, V, CAP> {
    fn default() -> Self {
        Self {
            array: Default::default(),
        }
    }
}

pub enum Entry<'a, K: 'a, V: 'a, const CAP: usize> {
    Occupied(OccupiedEntry<'a, K, V, CAP>),
    Vacant(VacantEntry<'a, K, V, CAP>),
}

pub struct OccupiedEntry<'a, K, V, const CAP: usize> {
    key: K,
    parent: &'a mut ArrayVec<(K, V), CAP>,
}

impl<'a, K, V, const CAP: usize> OccupiedEntry<'a, K, V, CAP>
where
    K: PartialEq,
{
    pub fn get(&self) -> &V {
        self.parent
            .iter()
            .find(|(k, _)| k == &self.key)
            .map(|(_, v)| v)
            .expect("entry should have a value")
    }

    pub fn get_mut(&mut self) -> &mut V {
        self.parent
            .iter_mut()
            .find(|(k, _)| k == &self.key)
            .map(|(_, v)| v)
            .expect("entry should have a value")
    }

    pub fn remove(&mut self) {
        self.parent.retain(|(k, _)| k != &self.key);
    }
}

pub struct VacantEntry<'a, K, V, const CAP: usize> {
    key: K,
    parent: &'a mut ArrayVec<(K, V), CAP>,
}

impl<'a, K, V, const CAP: usize> VacantEntry<'a, K, V, CAP> {
    pub fn insert(self, value: V) -> Result<(), V> {
        self.parent
            .try_push((self.key, value))
            .map_err(|e| e.element().1)
    }
}

impl<K, V, const CAP: usize> Map<K, V, CAP> {
    pub fn new() -> Self {
        Self {
            array: ArrayVec::<(K, V), CAP>::new_const(),
        }
    }

    pub fn len(&self) -> usize {
        self.array.len()
    }

    pub fn is_empty(&self) -> bool {
        self.array.is_empty()
    }

    pub fn entry(&mut self, entry_key: K) -> Entry<K, V, CAP>
    where
        K: Eq,
    {
        if let Some(_) = self.array.iter().find(|(k, _)| k == &entry_key) {
            return Entry::Occupied(OccupiedEntry {
                key: entry_key,
                parent: &mut self.array,
            });
        }
        Entry::Vacant(VacantEntry {
            key: entry_key,
            parent: &mut self.array,
        })
    }

    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, V>
    where
        K: Eq,
    {
        let element = self.remove(&key);
        self.array
            .try_push((key, value))
            .map(|_| element)
            .map_err(|e| e.element().1)
    }

    pub fn contains_key(&self, key: &K) -> bool
    where
        K: Eq,
    {
        self.array
            .iter()
            .find(|(k, _)| k == key)
            .map(|_| true)
            .unwrap_or(false)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V>
    where
        K: Eq,
    {
        self.array
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn get(&self, key: &K) -> Option<&V>
    where
        K: Eq,
    {
        self.array.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &K) -> Option<V>
    where
        K: Eq,
    {
        let pos = self.iter().position(|(k, _)| k == key);
        pos.and_then(|i| self.array.pop_at(i).map(|(_, v)| v))
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut K, &mut V) -> bool,
    {
        self.array.retain(|(k, v)| f(k, v));
    }

    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.into_iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (K, V)> {
        self.into_iter()
    }
}

impl<K, V, const CAP: usize> core::ops::Index<&K> for Map<K, V, CAP>
where
    K: Eq,
{
    type Output = V;

    fn index(&self, key: &K) -> &Self::Output {
        self.array
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .expect("value expected")
    }
}

impl<K, V, const CAP: usize> IntoIterator for Map<K, V, CAP> {
    type Item = (K, V);
    type IntoIter = <ArrayVec<(K, V), CAP> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.array.into_iter()
    }
}

impl<'a, K, V, const CAP: usize> IntoIterator for &'a Map<K, V, CAP> {
    type Item = &'a (K, V);
    type IntoIter = <&'a ArrayVec<(K, V), CAP> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.array.iter()
    }
}

impl<'a, K, V, const CAP: usize> IntoIterator for &'a mut Map<K, V, CAP> {
    type Item = &'a mut (K, V);
    type IntoIter = <&'a mut ArrayVec<(K, V), CAP> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.array.iter_mut()
    }
}

impl<K, V, const CAP: usize> FromIterator<(K, V)> for Map<K, V, CAP>
where
    K: Eq,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut c = Map::new();
        for (k, v) in iter {
            let _ = c.insert(k, v);
        }
        c
    }
}

impl<'a, K, V, const CAP: usize> FromIterator<&'a (K, V)> for Map<&'a K, &'a V, CAP>
where
    K: Eq,
{
    fn from_iter<I: IntoIterator<Item = &'a (K, V)>>(iter: I) -> Self {
        let mut c = Map::new();
        for (k, v) in iter {
            let _ = c.insert(k, v);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_basic_ops() {
        let mut map = Map::<u8, u8, 3>::new();

        assert!(map.is_empty());
        map.insert(1, 1).unwrap();
        map.insert(2, 2).unwrap();
        map.insert(3, 3).unwrap();
        assert!(!map.is_empty());
        assert_eq!(map.len(), 3);

        assert_eq!(map.remove(&4), None);

        assert!(map.contains_key(&3));
        assert_eq!(map.remove(&3), Some(3));
        assert!(!map.contains_key(&3));

        assert_eq!(map.len(), 2);
        assert_eq!(map.insert(1, 2), Ok(Some(1)));
        assert_eq!(map.len(), 2);

        assert_eq!(map[&1], 2);

        let mut iter = map.into_iter();
        assert_eq!(iter.next(), Some((2, 2)));
        assert_eq!(iter.next(), Some((1, 2)));
        assert_eq!(iter.next(), None);

        let mut map: Map<u8, u8, 100> = [(1, 1), (2, 2), (3, 3)].into_iter().collect();
        assert_eq!(map.len(), 3);
        map.retain(|k, _v| *k != 2);
        assert_eq!(map.len(), 2);
    }

    // #[test]
    // #[should_panic]
    // fn test_capacity() {
    //     let mut map = Map::<u8, u8, 1>::new();
    //     map.insert(1, 1);
    //     assert_eq!(map.len(), 1);
    //     map.insert(1, 2);
    //     assert_eq!(map.len(), 1);
    //     map.insert(2, 2);
    // }

    // #[test]
    // #[should_panic]
    // fn test_capacity_from_iter() {
    //     let mut map: Map<u8, u8, 1> = [(1, 1), (2, 2), (3, 3)].into_iter().collect();
    // }
}
