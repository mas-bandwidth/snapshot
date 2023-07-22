
solution "snapshot"
	platforms { "portable", "x86", "x64", "avx", "avx2" }
	configurations { "Debug", "Release" }
	targetdir "bin/"
	rtti "Off"
	warnings "Extra"
	floatingpoint "Fast"
	defines { "SNAPSHOT_DEVELOPMENT=1" }
	flags { "FatalWarnings" }
	filter "configurations:Debug"
		symbols "On"
		defines { "_DEBUG" }
	filter "configurations:Release"
		optimize "Speed"
		defines { "NDEBUG" }
		editandcontinue "Off"
	filter "system:windows"
		location ("visualstudio")
	filter "platforms:*x86"
		architecture "x86"
	filter "platforms:*x64 or *avx or *avx2"
		architecture "x86_64"

project "snapshot"
	kind "StaticLib"
	links { "sodium" }
	files {
		"include/*.h",
		"source/*.h",
		"source/*.c",
		"source/*.cpp",
	}
	includedirs { "include", "sodium" }
	filter "system:windows"
		linkoptions { "/ignore:4221" }
		disablewarnings { "4324" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }

project "sodium"
	kind "StaticLib"
	includedirs { "sodium" }
	files {
		"sodium/**.c",
		"sodium/**.h",
	}
  	filter { "system:not windows", "platforms:*x64 or *avx or *avx2" }
		files {
			"sodium/**.S"
		}
	filter "platforms:*x86"
		architecture "x86"
		defines { "SNAPSHOT_X86=1", "SNAPSHOT_CRYPTO_LOGS=1" }
	filter "platforms:*x64"
		architecture "x86_64"
		defines { "SNAPSHOT_X64=1", "SNAPSHOT_CRYPTO_LOGS=1" }
	filter "platforms:*avx"
		architecture "x86_64"
		vectorextensions "AVX"
		defines { "SNAPSHOT_X64=1", "SNAPSHOT_AVX=1", "SNAPSHOT_CRYPTO_LOGS=1" }
	filter "platforms:*avx2"
		architecture "x86_64"
		vectorextensions "AVX2"
		defines { "SNAPSHOT_X64=1", "SNAPSHOT_AVX=1", "SNAPSHOT_AVX2=1", "SNAPSHOT_CRYPTO_LOGS=1" }
	filter "system:windows"
		disablewarnings { "4221", "4244", "4715", "4197", "4146", "4324", "4456", "4100", "4459", "4245" }
		linkoptions { "/ignore:4221" }
	filter { "action:gmake" }
  		buildoptions { "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-unknown-pragmas", "-Wno-unused-variable", "-Wno-type-limits" }

project "test"
	kind "ConsoleApp"
	links { "snapshot", "sodium" }
	files { "test.cpp" }
	includedirs { "include", "source" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }

project "client"
	kind "ConsoleApp"
	links { "snapshot", "sodium" }
	files { "client.cpp" }
	includedirs { "include", "source" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }

project "server"
	kind "ConsoleApp"
	links { "snapshot", "sodium" }
	files { "server.cpp" }
	includedirs { "include", "source" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }

project "listen"
	kind "ConsoleApp"
	links { "snapshot", "sodium" }
	files { "listen.cpp" }
	includedirs { "include", "source" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }
