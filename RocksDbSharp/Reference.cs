namespace RocksDbSharp
{
    internal class RocksdbReferences
    {
        internal RocksdbReferences Options;
        internal RocksdbReferences[] CfOptions;
        internal BloomFilterPolicy FilterPolicy;
        internal EnvOptions EnvOptions;
        internal Cache BlockCache;
        internal ColumnFamilyOptions IoOptions;
        internal SliceTransform PrefixExtractor;
        internal BlockBasedTableOptions BlockBasedTableFactory;
    }
}
