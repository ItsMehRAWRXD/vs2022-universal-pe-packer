#ifndef PLUGIN_INCLUDES_H
#define PLUGIN_INCLUDES_H

// Forward declarations for plugin classes
namespace BenignPacker {
    class UniqueStub71Plugin;
    class MASMAssemblerPlugin;
}

// Include the actual plugin implementations
#include "UniqueStub71Plugin.h"
#include "MASMAssemblerPlugin.cpp"

#endif // PLUGIN_INCLUDES_H