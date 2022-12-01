using NativeImport;
using System;
using System.Collections.Generic;
using System.Text;

namespace RocksDbSharp
{
    class Native_Impl : Native
    {
        INativeLibImporter importer;
        IntPtr lib;
        public Native_Impl(INativeLibImporter posixImporter, IntPtr libHandle)
        {
            importer = posixImporter;
            lib = libHandle;
        }

        public T GetDelegate<T>(string entryPoint) where T : MulticastDelegate
        {
            return Importers.GetDelegate<T>(importer, lib, entryPoint);
        }

        public override IntPtr rocksdb_approximate_memory_usage_create(IntPtr consumers, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_approximate_memory_usage_destroy(IntPtr usage)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_approximate_memory_usage_get_cache_total(IntPtr memory_usage)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_approximate_memory_usage_get_mem_table_readers_total(IntPtr memory_usage)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_approximate_memory_usage_get_mem_table_total(IntPtr memory_usage)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_approximate_memory_usage_get_mem_table_unflushed(IntPtr memory_usage)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_approximate_sizes(IntPtr db, int num_ranges, IntPtr range_start_key, IntPtr range_start_key_len, IntPtr range_limit_key, IntPtr range_limit_key_len, IntPtr sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_approximate_sizes_cf(IntPtr db, IntPtr column_family, int num_ranges, IntPtr range_start_key, IntPtr range_start_key_len, IntPtr range_limit_key, IntPtr range_limit_key_len, IntPtr sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_close(IntPtr be)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_create_new_backup(IntPtr be, IntPtr db, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_create_new_backup_flush(IntPtr be, IntPtr db, bool flush_before_backup, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_backup_engine_get_backup_info(IntPtr be)
        {
            throw new NotImplementedException();
        }

        public override uint rocksdb_backup_engine_info_backup_id(IntPtr info, int index)
        {
            throw new NotImplementedException();
        }

        public override int rocksdb_backup_engine_info_count(IntPtr info)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_info_destroy(IntPtr info)
        {
            throw new NotImplementedException();
        }

        public override uint rocksdb_backup_engine_info_number_files(IntPtr info, int index)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_backup_engine_info_size(IntPtr info, int index)
        {
            throw new NotImplementedException();
        }

        public override long rocksdb_backup_engine_info_timestamp(IntPtr info, int index)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_backup_engine_open(IntPtr options, IntPtr path, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_backup_engine_open(IntPtr options, string path, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_purge_old_backups(IntPtr be, uint num_backups_to_keep, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_restore_db_from_latest_backup(IntPtr be, IntPtr db_dir, IntPtr wal_dir, IntPtr restore_options, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_restore_db_from_latest_backup(IntPtr be, string db_dir, string wal_dir, IntPtr restore_options, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_backup_engine_verify_backup(IntPtr be, uint backup_id, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_block_based_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_destroy(IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_block_cache(IntPtr options, IntPtr block_cache)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_block_cache_compressed(IntPtr options, IntPtr block_cache_compressed)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_block_restart_interval(IntPtr options, int block_restart_interval)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_block_size(IntPtr options, UIntPtr block_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_block_size_deviation(IntPtr options, int block_size_deviation)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_cache_index_and_filter_blocks(IntPtr block_based_table_options, bool cache_index_and_filter_blocks)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_cache_index_and_filter_blocks_with_high_priority(IntPtr block_based_table_options, bool cache_index_and_filter_blocks_with_high_priority)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_filter_policy(IntPtr options, IntPtr filter_policy)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_format_version(IntPtr block_based_table_options, int format_version)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_hash_index_allow_collision(IntPtr block_based_table_options, bool hash_index_allow_collision)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_index_block_restart_interval(IntPtr options, int index_block_restart_interval)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_index_type(IntPtr block_based_table_options, int index_type)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_index_type(IntPtr block_based_table_options, BlockBasedTableIndexType index_type)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_metadata_block_size(IntPtr options, ulong metadata_block_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_no_block_cache(IntPtr options, bool no_block_cache)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_partition_filters(IntPtr options, bool partition_filters)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_pin_l0_filter_and_index_blocks_in_cache(IntPtr block_based_table_options, bool pin_l0_filter_and_index_blocks_in_cache)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_pin_top_level_index_and_filter(IntPtr block_based_table_options, bool pin_top_level_index_and_filter)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_use_delta_encoding(IntPtr options, bool use_delta_encoding)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_block_based_options_set_whole_key_filtering(IntPtr block_based_table_options, bool whole_key_filtering)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_cache_create_lru(UIntPtr capacity)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cache_destroy(IntPtr cache)
        {
            throw new NotImplementedException();
        }

        public override UIntPtr rocksdb_cache_get_pinned_usage(IntPtr cache)
        {
            throw new NotImplementedException();
        }

        public override UIntPtr rocksdb_cache_get_usage(IntPtr cache)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cache_set_capacity(IntPtr cache, UIntPtr capacity)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_checkpoint_create_intptr(IntPtr checkpoint, IntPtr checkpoint_dir, ulong log_size_for_flush, out IntPtr errptr);
        delt_rocksdb_checkpoint_create_intptr rocksdb_checkpoint_create_func_intptr;
        public override void rocksdb_checkpoint_create(IntPtr checkpoint, IntPtr checkpoint_dir, ulong log_size_for_flush, out IntPtr errptr)
        {
            if (null == rocksdb_checkpoint_create_func_intptr)
            {
                rocksdb_checkpoint_create_func_intptr = GetDelegate<delt_rocksdb_checkpoint_create_intptr>("rocksdb_checkpoint_create");
            }
            rocksdb_checkpoint_create_func_intptr.Invoke(checkpoint, checkpoint_dir, log_size_for_flush, out errptr);
        }

        public delegate void delt_rocksdb_checkpoint_create_str(IntPtr checkpoint, string checkpoint_dir, ulong log_size_for_flush, out IntPtr errptr);
        delt_rocksdb_checkpoint_create_str rocksdb_checkpoint_create_func_str;
        public override void rocksdb_checkpoint_create(IntPtr checkpoint, string checkpoint_dir, ulong log_size_for_flush, out IntPtr errptr)
        {
            if (null == rocksdb_checkpoint_create_func_str)
            {
                rocksdb_checkpoint_create_func_str = GetDelegate<delt_rocksdb_checkpoint_create_str>("rocksdb_checkpoint_create");
            }
            rocksdb_checkpoint_create_func_str.Invoke(checkpoint, checkpoint_dir, log_size_for_flush, out errptr);
        }

        public delegate IntPtr delt_rocksdb_checkpoint_object_create(IntPtr db, out IntPtr errptr);
        delt_rocksdb_checkpoint_object_create rocksdb_checkpoint_object_create_func;
        public override IntPtr rocksdb_checkpoint_object_create(IntPtr db, out IntPtr errptr)
        {
            if (null == rocksdb_checkpoint_object_create_func)
            {
                rocksdb_checkpoint_object_create_func = GetDelegate<delt_rocksdb_checkpoint_object_create>("rocksdb_checkpoint_object_create");
            }
            return rocksdb_checkpoint_object_create_func.Invoke(db, out errptr);
        }

        public delegate void delt_rocksdb_checkpoint_object_destroy(IntPtr checkpoint);
        delt_rocksdb_checkpoint_object_destroy rocksdb_checkpoint_object_destroy_func;
        public override void rocksdb_checkpoint_object_destroy(IntPtr checkpoint)
        {
            if (null == rocksdb_checkpoint_object_destroy_func)
            {
                rocksdb_checkpoint_object_destroy_func = GetDelegate<delt_rocksdb_checkpoint_object_destroy>("rocksdb_checkpoint_object_destroy");
            }
            rocksdb_checkpoint_object_destroy_func.Invoke(checkpoint);
        }

        public delegate void delt_rocksdb_close(IntPtr db);
        delt_rocksdb_close rocksdb_close_func;

        public override void rocksdb_close(IntPtr db)
        {
            if (null == rocksdb_close_func)
            {
                rocksdb_close_func = GetDelegate<delt_rocksdb_close>("rocksdb_close");
            }
            rocksdb_close_func.Invoke(db);
        }

        public delegate void delt_rocksdb_column_family_handle_destroy(IntPtr column_family_handle);
        delt_rocksdb_column_family_handle_destroy rocksdb_column_family_handle_destroy_func;
        public override void rocksdb_column_family_handle_destroy(IntPtr column_family_handle)
        {
            if (null == rocksdb_column_family_handle_destroy_func)
            {
                rocksdb_column_family_handle_destroy_func = GetDelegate<delt_rocksdb_column_family_handle_destroy>("rocksdb_column_family_handle_destroy");
            }
            rocksdb_column_family_handle_destroy_func.Invoke(column_family_handle);
        }

        public override bool rocksdb_compactionfiltercontext_is_full_compaction(IntPtr context)
        {
            throw new NotImplementedException();
        }

        public override bool rocksdb_compactionfiltercontext_is_manual_compaction(IntPtr context)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_compactionfilterfactory_create(IntPtr state, IntPtr destructor, IntPtr create_compaction_filter, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_compactionfilterfactory_create(IntPtr state, DestructorDelegate destructor, CreateCompactionFilterDelegate create_compaction_filter, NameDelegate name)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactionfilterfactory_destroy(IntPtr compactionfilterfactory)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_compactionfilter_create(IntPtr state, IntPtr destructor, IntPtr filter, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_compactionfilter_create(IntPtr state, DestructorDelegate destructor, FilterDelegate filter, NameDelegate name)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactionfilter_destroy(IntPtr compactionfilter)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactionfilter_set_ignore_snapshots(IntPtr compactionfilter, bool ignore_snapshots)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_compactoptions_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactoptions_destroy(IntPtr compactoptions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactoptions_set_bottommost_level_compaction(IntPtr compactoptions, bool bottommost_level_compaction)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactoptions_set_change_level(IntPtr compactoptions, bool change_level)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactoptions_set_exclusive_manual_compaction(IntPtr compactoptions, bool exclusive_manual_compaction)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compactoptions_set_target_level(IntPtr compactoptions, int target_level)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range(IntPtr db, IntPtr start_key, UIntPtr start_key_len, IntPtr limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_compact_range(IntPtr db, byte* start_key, UIntPtr start_key_len, byte* limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range(IntPtr db, byte[] start_key, UIntPtr start_key_len, byte[] limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range_cf(IntPtr db, IntPtr column_family, IntPtr start_key, UIntPtr start_key_len, IntPtr limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_compact_range_cf(IntPtr db, IntPtr column_family, byte* start_key, UIntPtr start_key_len, byte* limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range_cf(IntPtr db, IntPtr column_family, byte[] start_key, UIntPtr start_key_len, byte[] limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range_cf_opt(IntPtr db, IntPtr column_family, IntPtr opt, IntPtr start_key, UIntPtr start_key_len, IntPtr limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_compact_range_cf_opt(IntPtr db, IntPtr column_family, IntPtr opt, byte* start_key, UIntPtr start_key_len, byte* limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range_cf_opt(IntPtr db, IntPtr column_family, IntPtr opt, byte[] start_key, UIntPtr start_key_len, byte[] limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range_opt(IntPtr db, IntPtr opt, IntPtr start_key, UIntPtr start_key_len, IntPtr limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_compact_range_opt(IntPtr db, IntPtr opt, byte* start_key, UIntPtr start_key_len, byte* limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_compact_range_opt(IntPtr db, IntPtr opt, byte[] start_key, UIntPtr start_key_len, byte[] limit_key, UIntPtr limit_key_len)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_comparator_create(IntPtr state, IntPtr destructor, IntPtr compare, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_comparator_create(IntPtr state, DestructorDelegate destructor, CompareDelegate compare, NameDelegate name)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_comparator_destroy(IntPtr comparator)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_create_column_family(IntPtr db, IntPtr column_family_options, IntPtr column_family_name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_create_column_family(IntPtr db, IntPtr column_family_options, string column_family_name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_create_default_env()
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb_create_iterator(IntPtr db, IntPtr options);
        delt_rocksdb_create_iterator rocksdb_create_iterator_func;
        public override IntPtr rocksdb_create_iterator(IntPtr db, IntPtr options)
        {
            if (null == rocksdb_create_iterator_func)
            {
                rocksdb_create_iterator_func = GetDelegate<delt_rocksdb_create_iterator>("rocksdb_create_iterator");
            }
            return rocksdb_create_iterator_func.Invoke(db, options);
        }

        public override void rocksdb_create_iterators(IntPtr db, IntPtr opts, IntPtr column_families, IntPtr iterators, UIntPtr size, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_create_iterators(IntPtr db, IntPtr opts, IntPtr[] column_families, IntPtr[] iterators, UIntPtr size, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb__create_iterator_cf(IntPtr db, IntPtr options, IntPtr column_family);
        delt_rocksdb__create_iterator_cf rocksdb_create_iterator_cf_func;

        public override IntPtr rocksdb_create_iterator_cf(IntPtr db, IntPtr options, IntPtr column_family)
        {
            if (null == rocksdb_create_iterator_cf_func)
            {
                rocksdb_create_iterator_cf_func = GetDelegate<delt_rocksdb__create_iterator_cf>("rocksdb_create_iterator_cf");
            }
            return rocksdb_create_iterator_cf_func.Invoke(db, options, column_family);
        }

        public override IntPtr rocksdb_create_mem_env()
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb_create_snapshot(IntPtr db);
        delt_rocksdb_create_snapshot rocksdb_create_snapshot_func;
        public override IntPtr rocksdb_create_snapshot(IntPtr db)
        {
            if (null == rocksdb_create_snapshot_func)
            {
                rocksdb_create_snapshot_func = GetDelegate<delt_rocksdb_create_snapshot>("rocksdb_create_snapshot");
            }
            return rocksdb_create_snapshot_func.Invoke(db);
        }

        public override IntPtr rocksdb_cuckoo_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cuckoo_options_destroy(IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cuckoo_options_set_cuckoo_block_size(IntPtr options, uint v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cuckoo_options_set_hash_ratio(IntPtr options, double v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cuckoo_options_set_identity_as_first_hash(IntPtr options, bool v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cuckoo_options_set_max_search_depth(IntPtr options, uint v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_cuckoo_options_set_use_module_hash(IntPtr options, bool v)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_dbpath_create(IntPtr path, ulong target_size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_dbpath_create(string path, ulong target_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_dbpath_destroy(IntPtr dbpath)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_delete_intptr(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, out IntPtr errptr);
        delt_rocksdb_delete_intptr rocksdb_delete_func_intptr;
        public override void rocksdb_delete(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, out IntPtr errptr)
        {
            if (null == rocksdb_delete_func_intptr)
            {
                rocksdb_delete_func_intptr = GetDelegate<delt_rocksdb_delete_intptr>("rocksdb_delete");
            }
            rocksdb_delete_func_intptr.Invoke(db, options, key, keylen, out errptr);
        }

        public unsafe delegate void delt_rocksdb_delete_ptr(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, out IntPtr errptr);
        delt_rocksdb_delete_ptr rocksdb_delete_func_ptr;
        public override unsafe void rocksdb_delete(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, out IntPtr errptr)
        {
            if (null == rocksdb_delete_func_ptr)
            {
                rocksdb_delete_func_ptr = GetDelegate<delt_rocksdb_delete_ptr>("rocksdb_delete");
            }
            rocksdb_delete_func_ptr.Invoke(db, options, key, keylen, out errptr);
        }

        public delegate void delt_rocksdb_delete_arr(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, out IntPtr errptr);
        delt_rocksdb_delete_arr rocksdb_delete_func_arr;
        public override void rocksdb_delete(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, out IntPtr errptr)
        {
            if (null == rocksdb_delete_func_arr)
            {
                rocksdb_delete_func_arr = GetDelegate<delt_rocksdb_delete_arr>("rocksdb_delete");
            }
            rocksdb_delete_func_arr.Invoke(db, options, key, keylen, out errptr);
        }

        public delegate void delt_rocksdb_delete_cf_intptr(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out IntPtr errptr);
        delt_rocksdb_delete_cf_intptr rocksdb_delete_cf_func_intptr;
        public override void rocksdb_delete_cf(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out IntPtr errptr)
        {
            if (null == rocksdb_delete_cf_func_intptr)
            {
                rocksdb_delete_cf_func_intptr = GetDelegate<delt_rocksdb_delete_cf_intptr>("rocksdb_delete_cf");
            }
            rocksdb_delete_cf_func_intptr.Invoke(db, options, column_family, key, keylen, out errptr);
        }

        public unsafe delegate void delt_rocksdb_delete_cf_ptr(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out IntPtr errptr);
        delt_rocksdb_delete_cf_ptr rocksdb_delete_cf_func_ptr;
        public override unsafe void rocksdb_delete_cf(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out IntPtr errptr)
        {
            if (null == rocksdb_delete_cf_func_ptr)
            {
                rocksdb_delete_cf_func_ptr = GetDelegate<delt_rocksdb_delete_cf_ptr>("rocksdb_delete_cf");
            }
            rocksdb_delete_cf_func_ptr.Invoke(db, options, column_family, key, keylen, out errptr);
        }

        public delegate void delt_rocksdb_delete_cf_arr(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out IntPtr errptr);
        delt_rocksdb_delete_cf_arr rocksdb_delete_cf_func_arr;
        public override void rocksdb_delete_cf(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out IntPtr errptr)
        {
            if (null == rocksdb_delete_cf_func_arr)
            {
                rocksdb_delete_cf_func_arr = GetDelegate<delt_rocksdb_delete_cf_arr>("rocksdb_delete_cf");
            }
            rocksdb_delete_cf_func_arr.Invoke(db, options, column_family, key, keylen, out errptr);
        }

        public override void rocksdb_delete_file(IntPtr db, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_delete_file(IntPtr db, string name)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_delete_file_in_range(IntPtr db, IntPtr start_key, UIntPtr start_key_len, IntPtr limit_key, UIntPtr limit_key_len, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_delete_file_in_range(IntPtr db, byte* start_key, UIntPtr start_key_len, byte* limit_key, UIntPtr limit_key_len, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_delete_file_in_range(IntPtr db, byte[] start_key, UIntPtr start_key_len, byte[] limit_key, UIntPtr limit_key_len, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_delete_file_in_range_cf(IntPtr db, IntPtr column_family, IntPtr start_key, UIntPtr start_key_len, IntPtr limit_key, UIntPtr limit_key_len, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_delete_file_in_range_cf(IntPtr db, IntPtr column_family, byte* start_key, UIntPtr start_key_len, byte* limit_key, UIntPtr limit_key_len, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_delete_file_in_range_cf(IntPtr db, IntPtr column_family, byte[] start_key, UIntPtr start_key_len, byte[] limit_key, UIntPtr limit_key_len, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_destroy_db(IntPtr options, IntPtr name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_destroy_db(IntPtr options, string name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_disable_file_deletions(IntPtr db, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_drop_column_family(IntPtr db, IntPtr handle, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_enable_file_deletions(IntPtr db, bool force, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_envoptions_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_envoptions_destroy(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_env_destroy(IntPtr env)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_env_join_all_threads(IntPtr env)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_env_set_background_threads(IntPtr env, int n)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_env_set_high_priority_background_threads(IntPtr env, int n)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_fifo_compaction_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_fifo_compaction_options_destroy(IntPtr fifo_opts)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_fifo_compaction_options_set_max_table_files_size(IntPtr fifo_opts, ulong size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_filterpolicy_create(IntPtr state, IntPtr destructor, IntPtr create_filter, IntPtr key_may_match, IntPtr delete_filter, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_filterpolicy_create(IntPtr state, DestructorDelegate destructor, CreateFilterDelegate create_filter, KeyMayMatchDelegate key_may_match, DeleteFilterDelegate delete_filter, NameDelegate name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_filterpolicy_create_bloom(int bits_per_key)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_filterpolicy_create_bloom_full(int bits_per_key)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_filterpolicy_destroy(IntPtr filterpolicy)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_flush(IntPtr db, IntPtr options, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_flushoptions_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_flushoptions_destroy(IntPtr flushoptions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_flushoptions_set_wait(IntPtr flushoptions, bool wait)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_flush_cf(IntPtr db, IntPtr options, IntPtr column_family, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_free(IntPtr ptr);
        delt_rocksdb_free rocksdb_free_func;
        public override void rocksdb_free(IntPtr ptr)
        {
            if (null == rocksdb_free_func)
            {
                rocksdb_free_func = GetDelegate<delt_rocksdb_free>("rocksdb_free");
            }
            rocksdb_free_func.Invoke(ptr);
        }

        public override IntPtr rocksdb_get(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public unsafe delegate IntPtr delt_rocksdb_get_ptr(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_get_ptr rocksdb_get_func_ptr;
        public override unsafe IntPtr rocksdb_get(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_get_func_ptr)
            {
                rocksdb_get_func_ptr = GetDelegate<delt_rocksdb_get_ptr>("rocksdb_get");
            }
            return rocksdb_get_func_ptr.Invoke(db, options, key, keylen, out vallen, out errptr);
        }

        public delegate IntPtr delt_rocksdb_get_arr(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_get_arr rocksdb_get_func_arr;
        public override IntPtr rocksdb_get(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_get_func_arr)
            {
                rocksdb_get_func_arr = GetDelegate<delt_rocksdb_get_arr>("rocksdb_get");
            }
            return rocksdb_get_func_arr.Invoke(db, options, key, keylen, out vallen, out errptr);
        }

        public override IntPtr rocksdb_get_cf(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_get_cf(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_get_cf(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_get_latest_sequence_number(IntPtr db)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_get_options_from_string(IntPtr base_options, IntPtr opts_str, IntPtr new_options, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_get_pinned(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_get_pinned(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_get_pinned(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_get_pinned_cf(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_get_pinned_cf(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_get_pinned_cf(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_get_updates_since(IntPtr db, ulong seq_number, IntPtr options, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_ingestexternalfileoptions_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingestexternalfileoptions_destroy(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingestexternalfileoptions_set_allow_blocking_flush(IntPtr opt, bool allow_blocking_flush)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingestexternalfileoptions_set_allow_global_seqno(IntPtr opt, bool allow_global_seqno)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingestexternalfileoptions_set_ingest_behind(IntPtr opt, bool ingest_behind)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingestexternalfileoptions_set_move_files(IntPtr opt, bool move_files)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingestexternalfileoptions_set_snapshot_consistency(IntPtr opt, bool snapshot_consistency)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingest_external_file(IntPtr db, string[] file_list, UIntPtr list_len, IntPtr opt, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingest_external_file(IntPtr db, IntPtr[] file_list, UIntPtr list_len, IntPtr opt, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingest_external_file_cf(IntPtr db, IntPtr handle, string[] file_list, UIntPtr list_len, IntPtr opt, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ingest_external_file_cf(IntPtr db, IntPtr handle, IntPtr[] file_list, UIntPtr list_len, IntPtr opt, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_iter_destroy(IntPtr iterator);
        delt_rocksdb_iter_destroy rocksdb_iter_destroy_func;
        public override void rocksdb_iter_destroy(IntPtr iterator)
        {
            if (null == rocksdb_iter_destroy_func)
            {
                rocksdb_iter_destroy_func = GetDelegate<delt_rocksdb_iter_destroy>("rocksdb_iter_destroy");
            }
            rocksdb_iter_destroy_func.Invoke(iterator);
        }

        public override void rocksdb_iter_get_error(IntPtr iterator, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb_iter_key(IntPtr iterator, out UIntPtr klen);
        delt_rocksdb_iter_key rocksdb_iter_key_func;
        public override IntPtr rocksdb_iter_key(IntPtr iterator, out UIntPtr klen)
        {
            if (null == rocksdb_iter_key_func)
            {
                rocksdb_iter_key_func = GetDelegate<delt_rocksdb_iter_key>("rocksdb_iter_key");
            }
            return rocksdb_iter_key_func.Invoke(iterator, out klen);
        }

        public delegate void delt_rocksdb_iter_next(IntPtr iterator);
        delt_rocksdb_iter_next rocksdb_iter_next_func;
        public override void rocksdb_iter_next(IntPtr iterator)
        {
            if (null == rocksdb_iter_next_func)
            {
                rocksdb_iter_next_func = GetDelegate<delt_rocksdb_iter_next>("rocksdb_iter_next");
            }
            rocksdb_iter_next_func.Invoke(iterator);
        }

        public override void rocksdb_iter_prev(IntPtr iterator)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_iter_seek_intptr(IntPtr iterator, IntPtr k, UIntPtr klen);
        delt_rocksdb_iter_seek_intptr rocksdb_iter_seek_func_intptr;
        public override void rocksdb_iter_seek(IntPtr iterator, IntPtr k, UIntPtr klen)
        {
            if (null == rocksdb_iter_seek_func_intptr)
            {
                rocksdb_iter_seek_func_intptr = GetDelegate<delt_rocksdb_iter_seek_intptr>("rocksdb_iter_seek");
            }
            rocksdb_iter_seek_func_intptr.Invoke(iterator, k, klen);
        }

        public unsafe delegate void delt_rocksdb_iter_seek_ptr(IntPtr iterator, byte* k, UIntPtr klen);
        delt_rocksdb_iter_seek_ptr rocksdb_iter_seek_func_ptr;
        public override unsafe void rocksdb_iter_seek(IntPtr iterator, byte* k, UIntPtr klen)
        {
            if (null == rocksdb_iter_seek_func_ptr)
            {
                rocksdb_iter_seek_func_ptr = GetDelegate<delt_rocksdb_iter_seek_ptr>("rocksdb_iter_seek");
            }
            rocksdb_iter_seek_func_ptr.Invoke(iterator, k, klen);
        }

        public delegate void delt_rocksdb_iter_seek_arr(IntPtr iterator, byte[] k, UIntPtr klen);
        delt_rocksdb_iter_seek_arr rocksdb_iter_seek_func_arr;
        public override void rocksdb_iter_seek(IntPtr iterator, byte[] k, UIntPtr klen)
        {
            if (null == rocksdb_iter_seek_func_arr)
            {
                rocksdb_iter_seek_func_arr = GetDelegate<delt_rocksdb_iter_seek_arr>("rocksdb_iter_seek");
            }
            rocksdb_iter_seek_func_arr.Invoke(iterator, k, klen);
        }

        public override void rocksdb_iter_seek_for_prev(IntPtr iterator, IntPtr k, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_iter_seek_for_prev(IntPtr iterator, byte* k, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_iter_seek_for_prev(IntPtr iterator, byte[] k, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_iter_seek_to_first(IntPtr iterator);
        delt_rocksdb_iter_seek_to_first rocksdb_iter_seek_to_first_func;
        public override void rocksdb_iter_seek_to_first(IntPtr iterator)
        {
            if (null == rocksdb_iter_seek_to_first_func)
            {
                rocksdb_iter_seek_to_first_func = GetDelegate<delt_rocksdb_iter_seek_to_first>("rocksdb_iter_seek_to_first");
            }
            rocksdb_iter_seek_to_first_func.Invoke(iterator);
        }

        public override void rocksdb_iter_seek_to_last(IntPtr iterator)
        {
            throw new NotImplementedException();
        }

        public delegate bool delt_rocksdb_iter_valid(IntPtr iterator);
        delt_rocksdb_iter_valid rocksdb_iter_valid_func;
        public override bool rocksdb_iter_valid(IntPtr iterator)
        {
            if (null == rocksdb_iter_valid_func)
            {
                rocksdb_iter_valid_func = GetDelegate<delt_rocksdb_iter_valid>("rocksdb_iter_valid");
            }
            return rocksdb_iter_valid_func.Invoke(iterator);
        }

        public delegate IntPtr delt_rocksdb_iter_value(IntPtr iterator, out UIntPtr vlen);
        delt_rocksdb_iter_value rocksdb_iter_value_func;
        public override IntPtr rocksdb_iter_value(IntPtr iterator, out UIntPtr vlen)
        {
            if (null == rocksdb_iter_value_func)
            {
                rocksdb_iter_value_func = GetDelegate<delt_rocksdb_iter_value>("rocksdb_iter_value");
            }
            return rocksdb_iter_value_func.Invoke(iterator, out vlen);
        }

        public delegate IntPtr delt_rocksdb_list_column_families_intptr(IntPtr options, IntPtr name, out UIntPtr lencf, out IntPtr errptr);
        delt_rocksdb_list_column_families_intptr rocksdb_list_column_families_func_intptr;
        public override IntPtr rocksdb_list_column_families(IntPtr options, IntPtr name, out UIntPtr lencf, out IntPtr errptr)
        {
            if (null == rocksdb_list_column_families_func_intptr)
            {
                rocksdb_list_column_families_func_intptr = GetDelegate<delt_rocksdb_list_column_families_intptr>("rocksdb_list_column_families");
            }
            return rocksdb_list_column_families_func_intptr.Invoke(options, name, out lencf, out errptr);
        }

        public delegate IntPtr delt_rocksdb_list_column_families_str(IntPtr options, string name, out UIntPtr lencf, out IntPtr errptr);
        delt_rocksdb_list_column_families_str rocksdb_list_column_families_func_str;
        public override IntPtr rocksdb_list_column_families(IntPtr options, string name, out UIntPtr lencf, out IntPtr errptr)
        {
            if (null == rocksdb_list_column_families_func_str)
            {
                rocksdb_list_column_families_func_str = GetDelegate<delt_rocksdb_list_column_families_str>("rocksdb_list_column_families");
            }
            return rocksdb_list_column_families_func_str.Invoke(options, name, out lencf, out errptr);
        }

        public delegate void delt_rocksdb_list_column_families_destroy_intptr(IntPtr list, UIntPtr len);
        delt_rocksdb_list_column_families_destroy_intptr rocksdb_list_column_families_destroy_func_intptr;
        public override void rocksdb_list_column_families_destroy(IntPtr list, UIntPtr len)
        {
            if (null == rocksdb_list_column_families_destroy_func_intptr)
            {
                rocksdb_list_column_families_destroy_func_intptr = GetDelegate<delt_rocksdb_list_column_families_destroy_intptr>("rocksdb_list_column_families_destroy");
            }
            rocksdb_list_column_families_destroy_func_intptr.Invoke(list, len);
        }

        public delegate void delt_rocksdb_list_column_families_destroy_arr(IntPtr[] list, UIntPtr len);
        delt_rocksdb_list_column_families_destroy_arr rocksdb_list_column_families_destroy_func_arr;
        public override void rocksdb_list_column_families_destroy(IntPtr[] list, UIntPtr len)
        {
            if (null == rocksdb_list_column_families_destroy_func_arr)
            {
                rocksdb_list_column_families_destroy_func_arr = GetDelegate<delt_rocksdb_list_column_families_destroy_arr>("rocksdb_list_column_families_destroy");
            }
            rocksdb_list_column_families_destroy_func_arr.Invoke(list, len);
        }

        public override IntPtr rocksdb_livefiles(IntPtr db)
        {
            throw new NotImplementedException();
        }

        public override int rocksdb_livefiles_count(IntPtr livefiles)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_livefiles_deletions(IntPtr livefiles, int index)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_livefiles_destroy(IntPtr livefiles)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_livefiles_entries(IntPtr livefiles, int index)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_livefiles_largestkey(IntPtr livefiles, int index, out UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override int rocksdb_livefiles_level(IntPtr livefiles, int index)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_livefiles_name(IntPtr livefiles, int index)
        {
            throw new NotImplementedException();
        }

        public override UIntPtr rocksdb_livefiles_size(IntPtr livefiles, int index)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_livefiles_smallestkey(IntPtr livefiles, int index, out UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_memory_consumers_add_cache(IntPtr consumers, IntPtr cache)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_memory_consumers_add_db(IntPtr consumers, IntPtr db)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_memory_consumers_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_memory_consumers_destroy(IntPtr consumers)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_merge(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_merge(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_merge(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_mergeoperator_create(IntPtr state, IntPtr destructor, IntPtr full_merge, IntPtr partial_merge, IntPtr delete_value, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_mergeoperator_create(IntPtr state, DestructorDelegate destructor, FullMergeDelegate full_merge, PartialMergeDelegate partial_merge, DeleteValueDelegate delete_value, NameDelegate name)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_mergeoperator_destroy(IntPtr mergeoperator)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_merge_cf(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_merge_cf(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_merge_cf(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_multi_get_intptr(IntPtr db, IntPtr options, UIntPtr num_keys, IntPtr keys_list, IntPtr keys_list_sizes, IntPtr values_list, IntPtr values_list_sizes, IntPtr[] errs);
        delt_rocksdb_multi_get_intptr rocksdb_multi_get_func_intptr;
        public override void rocksdb_multi_get(IntPtr db, IntPtr options, UIntPtr num_keys, IntPtr keys_list, IntPtr keys_list_sizes, IntPtr values_list, IntPtr values_list_sizes, IntPtr[] errs)
        {
            if (null == rocksdb_multi_get_func_intptr)
            {
                rocksdb_multi_get_func_intptr = GetDelegate<delt_rocksdb_multi_get_intptr>("rocksdb_multi_get");
            }
            rocksdb_multi_get_func_intptr.Invoke(db, options, num_keys, keys_list, keys_list_sizes, values_list, values_list_sizes, errs);
        }

        public delegate void delt_rocksdb_multi_get_arr(IntPtr db, IntPtr options, UIntPtr num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, IntPtr[] values_list, UIntPtr[] values_list_sizes, IntPtr[] errs);
        delt_rocksdb_multi_get_arr rocksdb_multi_get_func_arr;
        public override void rocksdb_multi_get(IntPtr db, IntPtr options, UIntPtr num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, IntPtr[] values_list, UIntPtr[] values_list_sizes, IntPtr[] errs)
        {
            if (null == rocksdb_multi_get_func_arr)
            {
                rocksdb_multi_get_func_arr = GetDelegate<delt_rocksdb_multi_get_arr>("rocksdb_multi_get");
            }
            rocksdb_multi_get_func_arr.Invoke(db, options, num_keys, keys_list, keys_list_sizes, values_list, values_list_sizes, errs);
        }


        public delegate void delt_rocksdb_multi_get_cf_intptr(IntPtr db, IntPtr options, IntPtr column_families, UIntPtr num_keys, IntPtr keys_list, IntPtr keys_list_sizes, IntPtr values_list, IntPtr values_list_sizes, IntPtr[] errs);
        delt_rocksdb_multi_get_cf_intptr rocksdb_multi_get_cf_func_intptr;
        public override void rocksdb_multi_get_cf(IntPtr db, IntPtr options, IntPtr column_families, UIntPtr num_keys, IntPtr keys_list, IntPtr keys_list_sizes, IntPtr values_list, IntPtr values_list_sizes, IntPtr[] errs)
        {
            if (null == rocksdb_multi_get_cf_func_intptr)
            {
                rocksdb_multi_get_cf_func_intptr = GetDelegate<delt_rocksdb_multi_get_cf_intptr>("rocksdb_multi_get_cf");
            }
            rocksdb_multi_get_cf_func_intptr(db, options, column_families, num_keys, keys_list, keys_list_sizes, values_list, values_list_sizes, errs);
        }

        public delegate void delt_rocksdb_multi_get_cf_arr(IntPtr db, IntPtr options, IntPtr[] column_families, UIntPtr num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, IntPtr[] values_list, UIntPtr[] values_list_sizes, IntPtr[] errs);
        delt_rocksdb_multi_get_cf_arr rocksdb_multi_get_cf_func_arr;
        public override void rocksdb_multi_get_cf(IntPtr db, IntPtr options, IntPtr[] column_families, UIntPtr num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, IntPtr[] values_list, UIntPtr[] values_list_sizes, IntPtr[] errs)
        {
            if (null == rocksdb_multi_get_cf_func_arr)
            {
                rocksdb_multi_get_cf_func_arr = GetDelegate<delt_rocksdb_multi_get_cf_arr>("rocksdb_multi_get_cf");
            }
            rocksdb_multi_get_cf_func_arr.Invoke(db, options, column_families, num_keys, keys_list, keys_list_sizes, values_list, values_list_sizes, errs);
        }

        delegate IntPtr delt_rocksdb_open_intptr(IntPtr options, IntPtr name, out IntPtr errptr);
        delt_rocksdb_open_intptr rocksdb_open_func_intptr;
        public override IntPtr rocksdb_open(IntPtr options, IntPtr name, out IntPtr errptr)
        {
            if (null == rocksdb_open_func_intptr)
            {
                rocksdb_open_func_intptr = GetDelegate<delt_rocksdb_open_intptr>("rocksdb_open");
            }
            return rocksdb_open_func_intptr.Invoke(options, name, out errptr);
        }

        public delegate IntPtr delt_rocksdb_open_str(IntPtr options, string name, out IntPtr errptr);
        delt_rocksdb_open_str rocksdb_open_func_str;
        public override IntPtr rocksdb_open(IntPtr options, string name, out IntPtr errptr)
        {
            if (null == rocksdb_open_func_str)
            {
                rocksdb_open_func_str = GetDelegate<delt_rocksdb_open_str>("rocksdb_open");
            }
            return rocksdb_open_func_str.Invoke(options, name, out errptr);
        }

        public delegate IntPtr delt_rocksdb_open_column_families_intptr_intptr(IntPtr options, IntPtr name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, out IntPtr errptr);
        delt_rocksdb_open_column_families_intptr_intptr rocksdb_open_column_families_func_intptr_intptr;
        public override IntPtr rocksdb_open_column_families(IntPtr options, IntPtr name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, out IntPtr errptr)
        {
            if (null == rocksdb_open_column_families_func_intptr_intptr)
            {
                rocksdb_open_column_families_func_intptr_intptr = GetDelegate<delt_rocksdb_open_column_families_intptr_intptr>("rocksdb_open_column_families");
            }
            return rocksdb_open_column_families_func_intptr_intptr.Invoke(options, name, num_column_families, column_family_names, column_family_options, column_family_handles, out errptr);
        }

        public delegate IntPtr delt_rocksdb_open_column_families_str_intptr(IntPtr options, string name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, out IntPtr errptr);
        delt_rocksdb_open_column_families_str_intptr rocksdb_open_column_families_func_str_intptr;
        public override IntPtr rocksdb_open_column_families(IntPtr options, string name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, out IntPtr errptr)
        {
            if (null == rocksdb_open_column_families_func_str_intptr)
            {
                rocksdb_open_column_families_func_str_intptr = GetDelegate<delt_rocksdb_open_column_families_str_intptr>("rocksdb_open_column_families");
            }
            return rocksdb_open_column_families_func_str_intptr.Invoke(options, name, num_column_families, column_family_names, column_family_options, column_family_handles, out errptr);
        }

        public delegate IntPtr delt_rocksdb_open_column_families_intptr_arr(IntPtr options, IntPtr name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, out IntPtr errptr);
        delt_rocksdb_open_column_families_intptr_arr rocksdb_open_column_families_func_intptr_arr;
        public override IntPtr rocksdb_open_column_families(IntPtr options, IntPtr name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, out IntPtr errptr)
        {
            if (null == rocksdb_open_column_families_func_intptr_arr)
            {
                rocksdb_open_column_families_func_intptr_arr = GetDelegate<delt_rocksdb_open_column_families_intptr_arr>("rocksdb_open_column_families");
            }
            return rocksdb_open_column_families_func_intptr_arr.Invoke(options, name, num_column_families, column_family_names, column_family_options, column_family_handles, out errptr);
        }

        public delegate IntPtr delt_rocksdb_open_column_families_str_arr(IntPtr options, string name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, out IntPtr errptr);
        delt_rocksdb_open_column_families_str_arr rocksdb_open_column_families_func_str_arr;
        public override IntPtr rocksdb_open_column_families(IntPtr options, string name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, out IntPtr errptr)
        {
            if (null == rocksdb_open_column_families_func_str_arr)
            {
                rocksdb_open_column_families_func_str_arr = GetDelegate<delt_rocksdb_open_column_families_str_arr>("rocksdb_open_column_families");
            }
            return rocksdb_open_column_families_func_str_arr.Invoke(options, name, num_column_families, column_family_names, column_family_options, column_family_handles, out errptr);
        }

        public override IntPtr rocksdb_open_for_read_only(IntPtr options, IntPtr name, bool error_if_log_file_exist, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_for_read_only(IntPtr options, string name, bool error_if_log_file_exist, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_for_read_only_column_families(IntPtr options, IntPtr name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, bool error_if_log_file_exist, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_for_read_only_column_families(IntPtr options, string name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, bool error_if_log_file_exist, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_for_read_only_column_families(IntPtr options, IntPtr name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, bool error_if_log_file_exist, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_for_read_only_column_families(IntPtr options, string name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, bool error_if_log_file_exist, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_with_ttl(IntPtr options, IntPtr name, int ttl, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_open_with_ttl(IntPtr options, string name, int ttl, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_optimistictransactiondb_close(IntPtr otxn_db)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_optimistictransactiondb_close_base_db(IntPtr base_db)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_get_base_db(IntPtr otxn_db)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_open(IntPtr options, IntPtr name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_open(IntPtr options, string name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_open_column_families(IntPtr options, IntPtr name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_open_column_families(IntPtr options, string name, int num_column_families, IntPtr column_family_names, IntPtr column_family_options, IntPtr column_family_handles, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_open_column_families(IntPtr options, IntPtr name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransactiondb_open_column_families(IntPtr options, string name, int num_column_families, string[] column_family_names, IntPtr[] column_family_options, IntPtr[] column_family_handles, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransaction_begin(IntPtr otxn_db, IntPtr write_options, IntPtr otxn_options, IntPtr old_txn)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_optimistictransaction_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_optimistictransaction_options_destroy(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_optimistictransaction_options_set_set_snapshot(IntPtr opt, bool v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_compaction_readahead_size(IntPtr options, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb_options_create();
        delt_rocksdb_options_create rocksdb_options_create_func;
        public override IntPtr rocksdb_options_create()
        {
            if (null == rocksdb_options_create_func)
            {
                rocksdb_options_create_func = GetDelegate<delt_rocksdb_options_create>("rocksdb_options_create");
            }
            return rocksdb_options_create_func.Invoke();
        }

        public delegate void delt_rocksdb_options_destroy(IntPtr options);
        delt_rocksdb_options_destroy rocksdb_options_destroy_func;
        public override void rocksdb_options_destroy(IntPtr options)
        {
            if (null == rocksdb_options_destroy_func)
            {
                rocksdb_options_destroy_func = GetDelegate<delt_rocksdb_options_destroy>("rocksdb_options_destroy");
            }
            rocksdb_options_destroy_func.Invoke(options);
        }

        public override void rocksdb_options_enable_statistics(IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_increase_parallelism(IntPtr opt, int total_threads)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_optimize_for_point_lookup(IntPtr opt, ulong block_cache_size_mb)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_optimize_level_style_compaction(IntPtr opt, ulong memtable_memory_budget)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_optimize_universal_style_compaction(IntPtr opt, ulong memtable_memory_budget)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_prepare_for_bulk_load(IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_access_hint_on_compaction_start(IntPtr options, int access_hint_on_compaction_start)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_advise_random_on_open(IntPtr options, bool advise_random_on_open)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_allow_concurrent_memtable_write(IntPtr options, bool allow_concurrent_memtable_write)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_allow_ingest_behind(IntPtr options, bool allow_ingest_behind)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_allow_mmap_reads(IntPtr options, bool allow_mmap_reads)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_allow_mmap_writes(IntPtr options, bool allow_mmap_writes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_arena_block_size(IntPtr options, UIntPtr arena_block_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_base_background_compactions(IntPtr options, int base_background_compactions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_block_based_table_factory(IntPtr opt, IntPtr table_options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_bloom_locality(IntPtr options, uint bloom_locality)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_bytes_per_sync(IntPtr options, ulong bytes_per_sync)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compaction_filter(IntPtr options, IntPtr compaction_filter)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compaction_filter_factory(IntPtr options, IntPtr compaction_filter_factory)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compaction_style(IntPtr options, int compaction_style)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compaction_style(IntPtr options, Compaction compaction_style)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_comparator(IntPtr options, IntPtr comparator)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compression(IntPtr options, int compression)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compression(IntPtr options, Compression compression)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compression_options(IntPtr options, int p1, int p2, int p3, int p4)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compression_per_level(IntPtr opt, int[] level_values, UIntPtr num_levels)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_compression_per_level(IntPtr opt, Compression[] level_values, UIntPtr num_levels)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_options_set_create_if_missing(IntPtr options, bool create_if_missing);
        delt_rocksdb_options_set_create_if_missing rocksdb_options_set_create_if_missing_func;
        public override void rocksdb_options_set_create_if_missing(IntPtr options, bool create_if_missing)
        {
            if (null == rocksdb_options_set_create_if_missing_func)
            {
                rocksdb_options_set_create_if_missing_func = GetDelegate<delt_rocksdb_options_set_create_if_missing>("rocksdb_options_set_create_if_missing");
            }
            rocksdb_options_set_create_if_missing_func.Invoke(options, create_if_missing);
        }

        public override void rocksdb_options_set_create_missing_column_families(IntPtr options, bool create_missing_column_families)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_cuckoo_table_factory(IntPtr opt, IntPtr table_options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_db_log_dir(IntPtr options, IntPtr db_log_dir)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_db_log_dir(IntPtr options, string db_log_dir)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_db_paths(IntPtr options, IntPtr path_values, UIntPtr num_paths)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_db_write_buffer_size(IntPtr options, UIntPtr db_write_buffer_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_delete_obsolete_files_period_micros(IntPtr options, ulong delete_obsolete_files_period_micros)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_disable_auto_compactions(IntPtr options, int disable_auto_compactions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_enable_pipelined_write(IntPtr options, bool enable_pipelined_write)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_enable_write_thread_adaptive_yield(IntPtr options, bool enable_write_thread_adaptive_yield)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_env(IntPtr options, IntPtr env)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_error_if_exists(IntPtr options, bool error_if_exists)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_fifo_compaction_options(IntPtr opt, IntPtr fifo)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_hard_pending_compaction_bytes_limit(IntPtr opt, UIntPtr v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_hard_rate_limit(IntPtr options, double hard_rate_limit)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_hash_link_list_rep(IntPtr options, UIntPtr hash_link_list_rep)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_hash_skip_list_rep(IntPtr options, UIntPtr size, int p2, int p3)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_info_log(IntPtr options, IntPtr info_log)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_info_log_level(IntPtr options, int info_log_level)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_inplace_update_num_locks(IntPtr options, UIntPtr inplace_update_num_locks)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_inplace_update_support(IntPtr options, bool inplace_update_support)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_is_fd_close_on_exec(IntPtr options, bool is_fd_close_on_exec)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_options_set_keep_log_file_num(IntPtr options, UIntPtr keep_log_file_num);
        delt_rocksdb_options_set_keep_log_file_num rocksdb_options_set_keep_log_file_num_func;
        public override void rocksdb_options_set_keep_log_file_num(IntPtr options, UIntPtr keep_log_file_num)
        {
            if (null == rocksdb_options_set_keep_log_file_num_func)
            {
                rocksdb_options_set_keep_log_file_num_func = GetDelegate<delt_rocksdb_options_set_keep_log_file_num>("rocksdb_options_set_keep_log_file_num");
            }
            rocksdb_options_set_keep_log_file_num_func.Invoke(options, keep_log_file_num);
        }

        public override void rocksdb_options_set_level0_file_num_compaction_trigger(IntPtr options, int level0_file_num_compaction_trigger)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_level0_slowdown_writes_trigger(IntPtr options, int level0_slowdown_writes_trigger)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_level0_stop_writes_trigger(IntPtr options, int level0_stop_writes_trigger)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_level_compaction_dynamic_level_bytes(IntPtr options, bool level_compaction_dynamic_level_bytes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_log_file_time_to_roll(IntPtr options, UIntPtr log_file_time_to_roll)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_manifest_preallocation_size(IntPtr options, UIntPtr manifest_preallocation_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_background_compactions(IntPtr options, int max_background_compactions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_background_flushes(IntPtr options, int max_background_flushes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_background_jobs(IntPtr options, int max_background_jobs)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_bytes_for_level_base(IntPtr options, ulong max_bytes_for_level_base)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_bytes_for_level_multiplier(IntPtr options, double max_bytes_for_level_multiplier)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_bytes_for_level_multiplier_additional(IntPtr options, IntPtr level_values, UIntPtr num_levels)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_bytes_for_level_multiplier_additional(IntPtr options, int[] level_values, UIntPtr num_levels)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_compaction_bytes(IntPtr options, ulong max_compaction_bytes)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_options_set_max_file_opening_threads(IntPtr options, int max_file_opening_threads);
        delt_rocksdb_options_set_max_file_opening_threads rocksdb_options_set_max_file_opening_threads_func;
        public override void rocksdb_options_set_max_file_opening_threads(IntPtr options, int max_file_opening_threads)
        {
            if (null == rocksdb_options_set_max_file_opening_threads_func)
            {
                rocksdb_options_set_max_file_opening_threads_func = GetDelegate<delt_rocksdb_options_set_max_file_opening_threads>("rocksdb_options_set_max_file_opening_threads");
            }
            rocksdb_options_set_max_file_opening_threads_func.Invoke(options, max_file_opening_threads);
        }

        public delegate void delt_rocksdb_options_set_max_log_file_size(IntPtr options, UIntPtr max_log_file_size);
        delt_rocksdb_options_set_max_log_file_size rocksdb_options_set_max_log_file_size_func;

        public override void rocksdb_options_set_max_log_file_size(IntPtr options, UIntPtr max_log_file_size)
        {
            if (null == rocksdb_options_set_max_log_file_size_func)
            {
                rocksdb_options_set_max_log_file_size_func = GetDelegate<delt_rocksdb_options_set_max_log_file_size>("rocksdb_options_set_max_log_file_size");
            }
            rocksdb_options_set_max_log_file_size_func.Invoke(options, max_log_file_size);
        }

        public override void rocksdb_options_set_max_manifest_file_size(IntPtr options, UIntPtr max_manifest_file_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_mem_compaction_level(IntPtr options, int max_mem_compaction_level)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_open_files(IntPtr options, int max_open_files)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_sequential_skip_in_iterations(IntPtr options, ulong max_sequential_skip_in_iterations)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_subcompactions(IntPtr options, uint max_subcompactions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_successive_merges(IntPtr options, UIntPtr max_successive_merges)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_total_wal_size(IntPtr opt, ulong n)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_write_buffer_number(IntPtr options, int max_write_buffer_number)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_max_write_buffer_number_to_maintain(IntPtr options, int max_write_buffer_number_to_maintain)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_memtable_huge_page_size(IntPtr options, UIntPtr memtable_huge_page_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_memtable_prefix_bloom_size_ratio(IntPtr options, double memtable_prefix_bloom_size_ratio)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_memtable_vector_rep(IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_merge_operator(IntPtr options, IntPtr merge_operator)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_min_level_to_compress(IntPtr opt, int level)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_min_write_buffer_number_to_merge(IntPtr options, int min_write_buffer_number_to_merge)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_num_levels(IntPtr options, int num_levels)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_optimize_filters_for_hits(IntPtr options, int optimize_filters_for_hits)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_paranoid_checks(IntPtr options, bool paranoid_checks)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_plain_table_factory(IntPtr options, uint p1, int p2, double p3, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_prefix_extractor(IntPtr options, IntPtr prefix_extractor)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_purge_redundant_kvs_while_flush(IntPtr options, bool purge_redundant_kvs_while_flush)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_ratelimiter(IntPtr opt, IntPtr limiter)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_rate_limit_delay_max_milliseconds(IntPtr options, uint rate_limit_delay_max_milliseconds)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_recycle_log_file_num(IntPtr options, UIntPtr recycle_log_file_num)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_report_bg_io_stats(IntPtr options, int report_bg_io_stats)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_skip_log_error_on_recovery(IntPtr options, bool skip_log_error_on_recovery)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_skip_stats_update_on_db_open(IntPtr opt, bool val)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_snap_refresh_nanos(IntPtr options, ulong snap_refresh_nanos)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_soft_pending_compaction_bytes_limit(IntPtr opt, UIntPtr v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_soft_rate_limit(IntPtr options, double soft_rate_limit)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_stats_dump_period_sec(IntPtr options, uint stats_dump_period_sec)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_table_cache_numshardbits(IntPtr options, int table_cache_numshardbits)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_table_cache_remove_scan_count_limit(IntPtr options, int table_cache_remove_scan_count_limit)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_target_file_size_base(IntPtr options, ulong target_file_size_base)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_target_file_size_multiplier(IntPtr options, int target_file_size_multiplier)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_uint64add_merge_operator(IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_universal_compaction_options(IntPtr options, IntPtr universal_compaction_options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_use_adaptive_mutex(IntPtr options, bool use_adaptive_mutex)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_use_direct_io_for_flush_and_compaction(IntPtr options, bool use_direct_io_for_flush_and_compaction)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_use_direct_reads(IntPtr options, bool use_direct_reads)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_use_fsync(IntPtr options, int use_fsync)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_wal_bytes_per_sync(IntPtr options, ulong wal_bytes_per_sync)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_wal_dir(IntPtr options, IntPtr wal_dir)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_wal_dir(IntPtr options, string wal_dir)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_wal_recovery_mode(IntPtr options, int wal_recovery_mode)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_wal_recovery_mode(IntPtr options, Recovery wal_recovery_mode)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_WAL_size_limit_MB(IntPtr options, ulong WAL_size_limit_MB)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_WAL_ttl_seconds(IntPtr options, ulong WAL_ttl_seconds)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_writable_file_max_buffer_size(IntPtr options, ulong writable_file_max_buffer_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_options_set_write_buffer_size(IntPtr options, UIntPtr write_buffer_size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_options_statistics_get_string(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_perfcontext_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_perfcontext_destroy(IntPtr context)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_perfcontext_metric(IntPtr context, int metric)
        {
            throw new NotImplementedException();
        }

        public override ulong rocksdb_perfcontext_metric(IntPtr context, PerfMetric metric)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_perfcontext_report(IntPtr context, bool exclude_zero_counters)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_perfcontext_reset(IntPtr context)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_pinnableslice_destroy(IntPtr v)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_pinnableslice_value(IntPtr t, out UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_property_value(IntPtr db, IntPtr propname)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_property_value(IntPtr db, string propname)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_property_value_cf(IntPtr db, IntPtr column_family, IntPtr propname)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_property_value_cf(IntPtr db, IntPtr column_family, string propname)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_put_intptr(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_put_intptr rocksdb_put_func_intptr;
        public override void rocksdb_put(IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_put_func_intptr)
            {
                rocksdb_put_func_intptr = GetDelegate<delt_rocksdb_put_intptr>("rocksdb_put");
            }
            rocksdb_put_func_intptr.Invoke(db, options, key, keylen, val, vallen, out errptr);
        }

        public unsafe delegate void delt_rocksdb_put_ptr(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_put_ptr rocksdb_put_func_ptr;
        public override unsafe void rocksdb_put(IntPtr db, IntPtr options, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_put_func_ptr)
            {
                rocksdb_put_func_ptr = GetDelegate<delt_rocksdb_put_ptr>("rocksdb_put");
            }
            rocksdb_put_func_ptr.Invoke(db, options, key, keylen, val, vallen, out errptr);
        }

        public delegate void delt_rocksdb_put_arr(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_put_arr rocksdb_put_func_arr;
        public override void rocksdb_put(IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_put_func_arr)
            {
                rocksdb_put_func_arr = GetDelegate<delt_rocksdb_put_arr>("rocksdb_put");
            }
            rocksdb_put_func_arr.Invoke(db, options, key, keylen, val, vallen, out errptr);
        }

        public delegate void delt_rocksdb_put_cf_intptr(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_put_cf_intptr rocksdb_put_cf_func_intptr;
        public override void rocksdb_put_cf(IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_put_cf_func_intptr)
            {
                rocksdb_put_cf_func_intptr = GetDelegate<delt_rocksdb_put_cf_intptr>("rocksdb_put_cf");
            }
            rocksdb_put_cf_func_intptr.Invoke(db, options, column_family, key, keylen, val, vallen, out errptr);
        }

        public unsafe delegate void delt_rocksdb_put_cf_ptr(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_put_cf_ptr rocksdb_put_cf_func_ptr;
        public override unsafe void rocksdb_put_cf(IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_put_cf_func_ptr)
            {
                rocksdb_put_cf_func_ptr = GetDelegate<delt_rocksdb_put_cf_ptr>("rocksdb_put_cf");
            }
            rocksdb_put_cf_func_ptr.Invoke(db, options, column_family, key, keylen, val, vallen, out errptr);
        }

        public delegate void delt_rocksdb_put_cf_arr(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr);
        delt_rocksdb_put_cf_arr rocksdb_put_cf_func_arr;
        public override void rocksdb_put_cf(IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            if (null == rocksdb_put_cf_func_arr)
            {
                rocksdb_put_cf_func_arr = GetDelegate<delt_rocksdb_put_cf_arr>("rocksdb_put_cf");
            }
            rocksdb_put_cf_func_arr.Invoke(db, options, column_family, key, keylen, val, vallen, out errptr);
        }

        public override IntPtr rocksdb_ratelimiter_create(long rate_bytes_per_sec, long refill_period_us, int fairness)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_ratelimiter_destroy(IntPtr ratelimiter)
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb_readoptions_create();
        delt_rocksdb_readoptions_create rocksdb_readoptions_create_func;
        public override IntPtr rocksdb_readoptions_create()
        {
            if (null == rocksdb_readoptions_create_func)
            {
                rocksdb_readoptions_create_func = GetDelegate<delt_rocksdb_readoptions_create>("rocksdb_readoptions_create");
            }
            return rocksdb_readoptions_create_func.Invoke();
        }

        public override void rocksdb_readoptions_destroy(IntPtr readoptions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_background_purge_on_iterator_cleanup(IntPtr readoptions, bool background_purge_on_iterator_cleanup)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_fill_cache(IntPtr readoptions, bool fill_cache)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_ignore_range_deletions(IntPtr readoptions, bool ignore_range_deletions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_iterate_lower_bound(IntPtr readoptions, IntPtr key, UIntPtr keylen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_readoptions_set_iterate_lower_bound(IntPtr readoptions, byte* key, UIntPtr keylen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_iterate_lower_bound(IntPtr readoptions, byte[] key, UIntPtr keylen)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_readoptions_set_iterate_upper_bound_intptr(IntPtr readoptions, IntPtr key, UIntPtr keylen);
        delt_rocksdb_readoptions_set_iterate_upper_bound_intptr rocksdb_readoptions_set_iterate_upper_bound_func;
        public override void rocksdb_readoptions_set_iterate_upper_bound(IntPtr readoptions, IntPtr key, UIntPtr keylen)
        {
            if (null == rocksdb_readoptions_set_iterate_upper_bound_func)
            {
                rocksdb_readoptions_set_iterate_upper_bound_func = GetDelegate<delt_rocksdb_readoptions_set_iterate_upper_bound_intptr>("rocksdb_readoptions_set_iterate_upper_bound");
            }
            rocksdb_readoptions_set_iterate_upper_bound_func.Invoke(readoptions, key, keylen);
        }

        public override unsafe void rocksdb_readoptions_set_iterate_upper_bound(IntPtr readoptions, byte* key, UIntPtr keylen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_iterate_upper_bound(IntPtr readoptions, byte[] key, UIntPtr keylen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_managed(IntPtr readoptions, bool managed)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_max_skippable_internal_keys(IntPtr readoptions, ulong max_skippable_internal_keys)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_pin_data(IntPtr readoptions, bool pin_data)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_prefix_same_as_start(IntPtr readoptions, bool prefix_same_as_start)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_readahead_size(IntPtr readoptions, UIntPtr readahead_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_read_tier(IntPtr readoptions, int read_tier)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_readoptions_set_snapshot(IntPtr readoptions, IntPtr snapshot);
        delt_rocksdb_readoptions_set_snapshot rocksdb_readoptions_set_snapshot_func;
        public override void rocksdb_readoptions_set_snapshot(IntPtr readoptions, IntPtr snapshot)
        {
            if (null == rocksdb_readoptions_set_snapshot_func)
            {
                rocksdb_readoptions_set_snapshot_func = GetDelegate<delt_rocksdb_readoptions_set_snapshot>("rocksdb_readoptions_set_snapshot");
            }
            rocksdb_readoptions_set_snapshot_func.Invoke(readoptions, snapshot);
        }

        public override void rocksdb_readoptions_set_tailing(IntPtr readoptions, bool tailing)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_total_order_seek(IntPtr readoptions, bool total_order_seek)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_readoptions_set_verify_checksums(IntPtr readoptions, bool verify_checksums)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_release_snapshot(IntPtr db, IntPtr snapshot);
        delt_rocksdb_release_snapshot rocksdb_release_snapshot_func;
        public override void rocksdb_release_snapshot(IntPtr db, IntPtr snapshot)
        {
            if (null == rocksdb_release_snapshot_func)
            {
                rocksdb_release_snapshot_func = GetDelegate<delt_rocksdb_release_snapshot>("rocksdb_release_snapshot");
            }
            rocksdb_release_snapshot_func.Invoke(db, snapshot);
        }

        public override void rocksdb_repair_db(IntPtr options, IntPtr name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_repair_db(IntPtr options, string name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_restore_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_restore_options_destroy(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_restore_options_set_keep_log_files(IntPtr opt, int v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_set_options(IntPtr db, int count, string[] keys, string[] values, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_set_options_cf(IntPtr db, IntPtr handle, int count, string[] keys, string[] values, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_set_perf_level(int perf_level)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_set_perf_level(PerfLevel perf_level)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_slicetransform_create(IntPtr state, IntPtr destructor, IntPtr transform, IntPtr in_domain, IntPtr in_range, IntPtr name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_slicetransform_create(IntPtr state, DestructorDelegate destructor, TransformDelegate transform, InDomainDelegate in_domain, InRangeDelegate in_range, NameDelegate name)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_slicetransform_create_fixed_prefix(UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_slicetransform_create_noop()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_slicetransform_destroy(IntPtr slicetransform)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_add(IntPtr writer, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_sstfilewriter_add(IntPtr writer, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_add(IntPtr writer, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_sstfilewriter_create(IntPtr env, IntPtr io_options)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_sstfilewriter_create_with_comparator(IntPtr env, IntPtr io_options, IntPtr comparator)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_delete(IntPtr writer, IntPtr key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_sstfilewriter_delete(IntPtr writer, byte* key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_delete(IntPtr writer, byte[] key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_destroy(IntPtr writer)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_file_size(IntPtr writer, IntPtr file_size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_finish(IntPtr writer, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_merge(IntPtr writer, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_sstfilewriter_merge(IntPtr writer, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_merge(IntPtr writer, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_open(IntPtr writer, IntPtr name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_open(IntPtr writer, string name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_put(IntPtr writer, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_sstfilewriter_put(IntPtr writer, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_sstfilewriter_put(IntPtr writer, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_checkpoint_object_create(IntPtr txn_db, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_close(IntPtr txn_db)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_create_column_family(IntPtr txn_db, IntPtr column_family_options, IntPtr column_family_name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_create_column_family(IntPtr txn_db, IntPtr column_family_options, string column_family_name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_create_iterator(IntPtr txn_db, IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_create_iterator_cf(IntPtr txn_db, IntPtr options, IntPtr column_family)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_create_snapshot(IntPtr txn_db)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_delete(IntPtr txn_db, IntPtr options, IntPtr key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transactiondb_delete(IntPtr txn_db, IntPtr options, byte* key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_delete(IntPtr txn_db, IntPtr options, byte[] key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_delete_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transactiondb_delete_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_delete_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_get(IntPtr txn_db, IntPtr options, IntPtr key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_transactiondb_get(IntPtr txn_db, IntPtr options, byte* key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_get(IntPtr txn_db, IntPtr options, byte[] key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_get_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_transactiondb_get_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_get_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_merge(IntPtr txn_db, IntPtr options, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transactiondb_merge(IntPtr txn_db, IntPtr options, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_merge(IntPtr txn_db, IntPtr options, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_merge_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transactiondb_merge_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_merge_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_open(IntPtr options, IntPtr txn_db_options, IntPtr name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_open(IntPtr options, IntPtr txn_db_options, string name, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transactiondb_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_options_destroy(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_options_set_default_lock_timeout(IntPtr opt, long default_lock_timeout)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_options_set_max_num_locks(IntPtr opt, long max_num_locks)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_options_set_num_stripes(IntPtr opt, UIntPtr num_stripes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_options_set_transaction_lock_timeout(IntPtr opt, long txn_lock_timeout)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_put(IntPtr txn_db, IntPtr options, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transactiondb_put(IntPtr txn_db, IntPtr options, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_put(IntPtr txn_db, IntPtr options, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_put_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, IntPtr val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transactiondb_put_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, byte* val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_put_cf(IntPtr txn_db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, byte[] val, UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_release_snapshot(IntPtr txn_db, IntPtr snapshot)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transactiondb_write(IntPtr txn_db, IntPtr options, IntPtr batch, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_begin(IntPtr txn_db, IntPtr write_options, IntPtr txn_options, IntPtr old_txn)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_commit(IntPtr txn, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_create_iterator(IntPtr txn, IntPtr options)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_create_iterator_cf(IntPtr txn, IntPtr options, IntPtr column_family)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_delete(IntPtr txn, IntPtr key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transaction_delete(IntPtr txn, byte* key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_delete(IntPtr txn, byte[] key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_delete_cf(IntPtr txn, IntPtr column_family, IntPtr key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transaction_delete_cf(IntPtr txn, IntPtr column_family, byte* key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_delete_cf(IntPtr txn, IntPtr column_family, byte[] key, UIntPtr klen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_destroy(IntPtr txn)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get(IntPtr txn, IntPtr options, IntPtr key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_transaction_get(IntPtr txn, IntPtr options, byte* key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get(IntPtr txn, IntPtr options, byte[] key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get_cf(IntPtr txn, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_transaction_get_cf(IntPtr txn, IntPtr options, IntPtr column_family, byte* key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get_cf(IntPtr txn, IntPtr options, IntPtr column_family, byte[] key, UIntPtr klen, out UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get_for_update(IntPtr txn, IntPtr options, IntPtr key, UIntPtr klen, out UIntPtr vlen, bool exclusive, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_transaction_get_for_update(IntPtr txn, IntPtr options, byte* key, UIntPtr klen, out UIntPtr vlen, bool exclusive, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get_for_update(IntPtr txn, IntPtr options, byte[] key, UIntPtr klen, out UIntPtr vlen, bool exclusive, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_get_snapshot(IntPtr txn)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_merge(IntPtr txn, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transaction_merge(IntPtr txn, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_merge(IntPtr txn, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_merge_cf(IntPtr txn, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transaction_merge_cf(IntPtr txn, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_merge_cf(IntPtr txn, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_transaction_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_destroy(IntPtr opt)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_set_deadlock_detect(IntPtr opt, bool v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_set_deadlock_detect_depth(IntPtr opt, long depth)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_set_expiration(IntPtr opt, long expiration)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_set_lock_timeout(IntPtr opt, long lock_timeout)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_set_max_write_batch_size(IntPtr opt, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_options_set_set_snapshot(IntPtr opt, bool v)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_put(IntPtr txn, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transaction_put(IntPtr txn, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_put(IntPtr txn, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_put_cf(IntPtr txn, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_transaction_put_cf(IntPtr txn, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_put_cf(IntPtr txn, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_rollback(IntPtr txn, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_rollback_to_savepoint(IntPtr txn, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_transaction_set_savepoint(IntPtr txn)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_universal_compaction_options_create()
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_destroy(IntPtr universal_compaction_options)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_set_compression_size_percent(IntPtr universal_compaction_options, int compression_size_percent)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_set_max_merge_width(IntPtr universal_compaction_options, int max_merge_width)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_set_max_size_amplification_percent(IntPtr universal_compaction_options, int max_size_amplification_percent)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_set_min_merge_width(IntPtr universal_compaction_options, int min_merge_width)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_set_size_ratio(IntPtr universal_compaction_options, int size_ratio)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_universal_compaction_options_set_stop_style(IntPtr universal_compaction_options, int stop_style)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_wal_iter_destroy(IntPtr iter)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_wal_iter_get_batch(IntPtr iter, IntPtr seq)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_wal_iter_next(IntPtr iter)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_wal_iter_status(IntPtr iter, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override bool rocksdb_wal_iter_valid(IntPtr wal_iterator)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_write(IntPtr db, IntPtr options, IntPtr batch, out IntPtr errptr);
        delt_rocksdb_write rocksdb_write_func;
        public override void rocksdb_write(IntPtr db, IntPtr options, IntPtr batch, out IntPtr errptr)
        {
            if (null == rocksdb_write_func)
            {
                rocksdb_write_func = GetDelegate<delt_rocksdb_write>("rocksdb_write");
            }
            rocksdb_write_func.Invoke(db, options, batch, out errptr);
        }

        public delegate void delt_rocksdb_writebatch_clear(IntPtr writebatch);
        delt_rocksdb_writebatch_clear rocksdb_writebatch_clear_func;
        public override void rocksdb_writebatch_clear(IntPtr writebatch)
        {
            if (null == rocksdb_writebatch_clear_func)
            {
                rocksdb_writebatch_clear_func = GetDelegate<delt_rocksdb_writebatch_clear>("rocksdb_writebatch_clear");
            }
            rocksdb_writebatch_clear_func.Invoke(writebatch);
        }

        public delegate int delt_rocksdb_writebatch_count(IntPtr writebatch);
        delt_rocksdb_writebatch_count rocksdb_writebatch_count_func;
        public override int rocksdb_writebatch_count(IntPtr writebatch)
        {
            if (null == rocksdb_writebatch_count_func)
            {
                rocksdb_writebatch_count_func = GetDelegate<delt_rocksdb_writebatch_count>("rocksdb_writebatch_count");
            }
            return rocksdb_writebatch_count_func.Invoke(writebatch);
        }

        public delegate IntPtr delt_rocksdb_writebatch_create();
        delt_rocksdb_writebatch_create rocksdb_writebatch_create_func;
        public override IntPtr rocksdb_writebatch_create()
        {
            if (null == rocksdb_writebatch_create_func)
            {
                rocksdb_writebatch_create_func = GetDelegate<delt_rocksdb_writebatch_create>("rocksdb_writebatch_create");
            }
            return rocksdb_writebatch_create_func.Invoke();
        }

        public override IntPtr rocksdb_writebatch_create_from(IntPtr rep, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_writebatch_create_from(byte* rep, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_create_from(byte[] rep, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_data(IntPtr writebatch, out UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete(IntPtr writebatch, IntPtr key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_delete(IntPtr writebatch, byte* key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_writebatch_delete(IntPtr writebatch, byte[] key, UIntPtr klen);
        delt_rocksdb_writebatch_delete rocksdb_writebatch_delete_func;
        public override void rocksdb_writebatch_delete(IntPtr writebatch, byte[] key, UIntPtr klen)
        {
            if (null == rocksdb_writebatch_delete_func)
            {
                rocksdb_writebatch_delete_func = GetDelegate<delt_rocksdb_writebatch_delete>("rocksdb_writebatch_delete");
            }
            rocksdb_writebatch_delete_func.Invoke(writebatch, key, klen);
        }

        public override void rocksdb_writebatch_deletev(IntPtr b, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_deletev(IntPtr b, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_deletev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_deletev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_cf(IntPtr writebatch, IntPtr column_family, IntPtr key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_delete_cf(IntPtr writebatch, IntPtr column_family, byte* key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_writebatch_delete_cf(IntPtr writebatch, IntPtr column_family, byte[] key, UIntPtr klen);
        delt_rocksdb_writebatch_delete_cf rocksdb_writebatch_delete_cf_func;
        public override void rocksdb_writebatch_delete_cf(IntPtr writebatch, IntPtr column_family, byte[] key, UIntPtr klen)
        {
            if (null == rocksdb_writebatch_delete_cf_func)
            {
                rocksdb_writebatch_delete_cf_func = GetDelegate<delt_rocksdb_writebatch_delete_cf>("rocksdb_writebatch_delete_cf");
            }
            rocksdb_writebatch_delete_cf_func.Invoke(writebatch, column_family, key, klen);
        }

        public override void rocksdb_writebatch_delete_range(IntPtr b, IntPtr start_key, UIntPtr start_key_len, IntPtr end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_delete_range(IntPtr b, byte* start_key, UIntPtr start_key_len, byte* end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_range(IntPtr b, byte[] start_key, UIntPtr start_key_len, byte[] end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_rangev(IntPtr b, int num_keys, IntPtr start_keys_list, IntPtr start_keys_list_sizes, IntPtr end_keys_list, IntPtr end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_rangev(IntPtr b, int num_keys, IntPtr[] start_keys_list, UIntPtr[] start_keys_list_sizes, IntPtr[] end_keys_list, UIntPtr[] end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_rangev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr start_keys_list, IntPtr start_keys_list_sizes, IntPtr end_keys_list, IntPtr end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_rangev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] start_keys_list, UIntPtr[] start_keys_list_sizes, IntPtr[] end_keys_list, UIntPtr[] end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_range_cf(IntPtr b, IntPtr column_family, IntPtr start_key, UIntPtr start_key_len, IntPtr end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_delete_range_cf(IntPtr b, IntPtr column_family, byte* start_key, UIntPtr start_key_len, byte* end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_delete_range_cf(IntPtr b, IntPtr column_family, byte[] start_key, UIntPtr start_key_len, byte[] end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_writebatch_destroy(IntPtr writebatch);
        delt_rocksdb_writebatch_destroy rocksdb_writebatch_destroy_func;
        public override void rocksdb_writebatch_destroy(IntPtr writebatch)
        {
            if (null == rocksdb_writebatch_destroy_func)
            {
                rocksdb_writebatch_destroy_func = GetDelegate<delt_rocksdb_writebatch_destroy>("rocksdb_writebatch_destroy");
            }
            rocksdb_writebatch_destroy_func.Invoke(writebatch);
        }

        public override void rocksdb_writebatch_iterate(IntPtr writebatch, IntPtr state, IntPtr put, IntPtr deleted)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_iterate(IntPtr writebatch, IntPtr state, PutDelegate put, DeletedDelegate deleted)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_merge(IntPtr writebatch, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_merge(IntPtr writebatch, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_merge(IntPtr writebatch, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_mergev(IntPtr b, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_mergev(IntPtr b, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_mergev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_mergev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_merge_cf(IntPtr writebatch, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_merge_cf(IntPtr writebatch, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_merge_cf(IntPtr writebatch, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_pop_save_point(IntPtr writebatch, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_put(IntPtr writebatch, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public unsafe delegate void delt_rocksdb_writebatch_put_ptr(IntPtr writebatch, byte* key, UIntPtr klen, byte* val, UIntPtr vlen);
        delt_rocksdb_writebatch_put_ptr rocksdb_writebatch_put_func_ptr;
        public override unsafe void rocksdb_writebatch_put(IntPtr writebatch, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            if (null == rocksdb_writebatch_put_func_ptr)
            {
                rocksdb_writebatch_put_func_ptr = GetDelegate<delt_rocksdb_writebatch_put_ptr>("rocksdb_writebatch_put");
            }
            rocksdb_writebatch_put_func_ptr.Invoke(writebatch, key, klen, val, vlen);
        }

        public delegate void delt_rocksdb_writebatch_put_arr(IntPtr writebatch, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen);
        delt_rocksdb_writebatch_put_arr rocksdb_writebatch_put_func_arr;
        public override void rocksdb_writebatch_put(IntPtr writebatch, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            if (null == rocksdb_writebatch_put_func_arr)
            {
                rocksdb_writebatch_put_func_arr = GetDelegate<delt_rocksdb_writebatch_put_arr>("rocksdb_writebatch_put");
            }
            rocksdb_writebatch_put_func_arr.Invoke(writebatch, key, klen, val, vlen);
        }

        public override void rocksdb_writebatch_putv(IntPtr b, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_putv(IntPtr b, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_putv_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_putv_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_put_cf(IntPtr writebatch, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_put_cf(IntPtr writebatch, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_writebatch_put_cf(IntPtr writebatch, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen);
        delt_rocksdb_writebatch_put_cf rocksdb_writebatch_put_cf_func;
        public override void rocksdb_writebatch_put_cf(IntPtr writebatch, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            if (null == rocksdb_writebatch_put_cf_func)
            {
                rocksdb_writebatch_put_cf_func = GetDelegate<delt_rocksdb_writebatch_put_cf>("rocksdb_writebatch_put_cf");
            }
            rocksdb_writebatch_put_cf_func.Invoke(writebatch, column_family, key, klen, val, vlen);
        }

        public override void rocksdb_writebatch_put_log_data(IntPtr writebatch, IntPtr blob, UIntPtr len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_put_log_data(IntPtr writebatch, byte* blob, UIntPtr len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_put_log_data(IntPtr writebatch, byte[] blob, UIntPtr len)
        {
            throw new NotImplementedException();
        }

        public delegate void delt_rocksdb_writebatch_rollback_to_save_point(IntPtr writebatch, out IntPtr errptr);
        delt_rocksdb_writebatch_rollback_to_save_point rocksdb_writebatch_rollback_to_save_point_func;
        public override void rocksdb_writebatch_rollback_to_save_point(IntPtr writebatch, out IntPtr errptr)
        {
            if (null == rocksdb_writebatch_rollback_to_save_point_func)
            {
                rocksdb_writebatch_rollback_to_save_point_func = GetDelegate<delt_rocksdb_writebatch_rollback_to_save_point>("rocksdb_writebatch_rollback_to_save_point");
            }
            rocksdb_writebatch_rollback_to_save_point_func.Invoke(writebatch, out errptr);
        }

        public delegate void delt_rocksdb_writebatch_set_save_point(IntPtr writebatch);
        delt_rocksdb_writebatch_set_save_point rocksdb_writebatch_set_save_point_func;
        public override void rocksdb_writebatch_set_save_point(IntPtr writebatch)
        {
            if (null == rocksdb_writebatch_set_save_point_func)
            {
                rocksdb_writebatch_set_save_point_func = GetDelegate<delt_rocksdb_writebatch_set_save_point>("rocksdb_writebatch_set_save_point");
            }
            rocksdb_writebatch_set_save_point_func.Invoke(writebatch);
        }

        public override void rocksdb_writebatch_wi_clear(IntPtr writebatch_wi)
        {
            throw new NotImplementedException();
        }

        public override int rocksdb_writebatch_wi_count(IntPtr b)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_create(UIntPtr reserved_bytes, bool overwrite_keys)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_create_from(IntPtr rep, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_writebatch_wi_create_from(byte* rep, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_create_from(byte[] rep, UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_create_iterator_with_base(IntPtr wbwi, IntPtr base_iterator)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_create_iterator_with_base_cf(IntPtr wbwi, IntPtr base_iterator, IntPtr cf)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_data(IntPtr b, out UIntPtr size)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete(IntPtr writebatch_wi, IntPtr key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_delete(IntPtr writebatch_wi, byte* key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete(IntPtr writebatch_wi, byte[] key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_deletev(IntPtr b, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_deletev(IntPtr b, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_deletev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_deletev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_cf(IntPtr writebatch_wi, IntPtr column_family, IntPtr key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_delete_cf(IntPtr writebatch_wi, IntPtr column_family, byte* key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_cf(IntPtr writebatch_wi, IntPtr column_family, byte[] key, UIntPtr klen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_range(IntPtr b, IntPtr start_key, UIntPtr start_key_len, IntPtr end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_delete_range(IntPtr b, byte* start_key, UIntPtr start_key_len, byte* end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_range(IntPtr b, byte[] start_key, UIntPtr start_key_len, byte[] end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_rangev(IntPtr b, int num_keys, IntPtr start_keys_list, IntPtr start_keys_list_sizes, IntPtr end_keys_list, IntPtr end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_rangev(IntPtr b, int num_keys, IntPtr[] start_keys_list, UIntPtr[] start_keys_list_sizes, IntPtr[] end_keys_list, UIntPtr[] end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_rangev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr start_keys_list, IntPtr start_keys_list_sizes, IntPtr end_keys_list, IntPtr end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_rangev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] start_keys_list, UIntPtr[] start_keys_list_sizes, IntPtr[] end_keys_list, UIntPtr[] end_keys_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_range_cf(IntPtr b, IntPtr column_family, IntPtr start_key, UIntPtr start_key_len, IntPtr end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_delete_range_cf(IntPtr b, IntPtr column_family, byte* start_key, UIntPtr start_key_len, byte* end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_delete_range_cf(IntPtr b, IntPtr column_family, byte[] start_key, UIntPtr start_key_len, byte[] end_key, UIntPtr end_key_len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_destroy(IntPtr writebatch_wi)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch(IntPtr wbwi, IntPtr options, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_writebatch_wi_get_from_batch(IntPtr wbwi, IntPtr options, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch(IntPtr wbwi, IntPtr options, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch_and_db(IntPtr wbwi, IntPtr db, IntPtr options, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_writebatch_wi_get_from_batch_and_db(IntPtr wbwi, IntPtr db, IntPtr options, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch_and_db(IntPtr wbwi, IntPtr db, IntPtr options, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch_and_db_cf(IntPtr wbwi, IntPtr db, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_writebatch_wi_get_from_batch_and_db_cf(IntPtr wbwi, IntPtr db, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch_and_db_cf(IntPtr wbwi, IntPtr db, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch_cf(IntPtr wbwi, IntPtr options, IntPtr column_family, IntPtr key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override unsafe IntPtr rocksdb_writebatch_wi_get_from_batch_cf(IntPtr wbwi, IntPtr options, IntPtr column_family, byte* key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override IntPtr rocksdb_writebatch_wi_get_from_batch_cf(IntPtr wbwi, IntPtr options, IntPtr column_family, byte[] key, UIntPtr keylen, out UIntPtr vallen, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_iterate(IntPtr b, IntPtr state, IntPtr put, IntPtr deleted)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_iterate(IntPtr b, IntPtr state, PutDelegate put, DeletedDelegate deleted)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_merge(IntPtr writebatch_wi, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_merge(IntPtr writebatch_wi, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_merge(IntPtr writebatch_wi, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_mergev(IntPtr b, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_mergev(IntPtr b, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_mergev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_mergev_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_merge_cf(IntPtr writebatch_wi, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_merge_cf(IntPtr writebatch_wi, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_merge_cf(IntPtr writebatch_wi, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_put(IntPtr writebatch_wi, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_put(IntPtr writebatch_wi, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_put(IntPtr writebatch_wi, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_putv(IntPtr b, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_putv(IntPtr b, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_putv_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr keys_list, IntPtr keys_list_sizes, int num_values, IntPtr values_list, IntPtr values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_putv_cf(IntPtr b, IntPtr column_family, int num_keys, IntPtr[] keys_list, UIntPtr[] keys_list_sizes, int num_values, IntPtr[] values_list, UIntPtr[] values_list_sizes)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_put_cf(IntPtr writebatch_wi, IntPtr column_family, IntPtr key, UIntPtr klen, IntPtr val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_put_cf(IntPtr writebatch_wi, IntPtr column_family, byte* key, UIntPtr klen, byte* val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_put_cf(IntPtr writebatch_wi, IntPtr column_family, byte[] key, UIntPtr klen, byte[] val, UIntPtr vlen)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_put_log_data(IntPtr writebatch_wi, IntPtr blob, UIntPtr len)
        {
            throw new NotImplementedException();
        }

        public override unsafe void rocksdb_writebatch_wi_put_log_data(IntPtr writebatch_wi, byte* blob, UIntPtr len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_put_log_data(IntPtr writebatch_wi, byte[] blob, UIntPtr len)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_rollback_to_save_point(IntPtr writebatch_wi, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writebatch_wi_set_save_point(IntPtr writebatch_wi)
        {
            throw new NotImplementedException();
        }

        public delegate IntPtr delt_rocksdb_writeoptions_create();
        delt_rocksdb_writeoptions_create rocksdb_writeoptions_create_func;
        public override IntPtr rocksdb_writeoptions_create()
        {
            if (null == rocksdb_writeoptions_create_func)
            {
                rocksdb_writeoptions_create_func = GetDelegate<delt_rocksdb_writeoptions_create>("rocksdb_writeoptions_create");
            }
            return rocksdb_writeoptions_create_func.Invoke();
        }

        public override void rocksdb_writeoptions_destroy(IntPtr writeoptions)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writeoptions_disable_WAL(IntPtr opt, int disable)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writeoptions_set_ignore_missing_column_families(IntPtr writeoptions, bool ignore_missing_column_families)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writeoptions_set_low_pri(IntPtr writeoptions, bool low_pri)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writeoptions_set_no_slowdown(IntPtr writeoptions, bool no_slowdown)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_writeoptions_set_sync(IntPtr writeoptions, bool sync)
        {
            throw new NotImplementedException();
        }

        public override void rocksdb_write_writebatch_wi(IntPtr db, IntPtr options, IntPtr wbwi, out IntPtr errptr)
        {
            throw new NotImplementedException();
        }
    }
}
