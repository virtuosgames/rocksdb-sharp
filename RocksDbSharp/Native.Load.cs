using NativeImport;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace RocksDbSharp
{
    public abstract partial class Native
    {
        public static Native Instance;

        public Native()
        {
        }

#if LIB9C_DEV_IL2CPP
        public static void LoadLibrary(string libPath)
        {
            if (!File.Exists(libPath))
            {
                throw new FileNotFoundException();
            }

            INativeLibImporter importer = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? Importers.Windows : Importers.Posix;
            IntPtr lib = importer.LoadLibrary(libPath);
            if (lib == IntPtr.Zero)
                throw new NativeLoadException("LoadLibrary returned 0", null);
            Instance = new Native_Impl(importer, lib);
        }
#else
    static Native()
    {
        if (RuntimeInformation.ProcessArchitecture == Architecture.X86 && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            throw new RocksDbSharpException("Rocksdb on windows is not supported for 32 bit applications");
        Instance = NativeImport.Auto.Import<Native>("rocksdb", "6.2.2", true);
    }
#endif
    }
}
