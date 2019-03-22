# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import plugin_object
import floss.interfaces as interfaces


class FunctionIsLibraryPlugin(plugin_object.GeneralPlugin):
    """
    Identify library functions. Score is 1.0 if function is library, 0.0 otherwise
    """
    implements = [interfaces.DecodingRoutineIdentifier]
    version = 1.0

    def identify(self, vivisect_workspace, function_vas):
        function_vas = function_vas - set(vivisect_workspace.getEntryPoints())
        candidate_functions = {}
        for fva in function_vas:
            fname = vivisect_workspace.getName(fva)
            default_prefix = "sub_"
            if fname is not None and not fname.startswith(default_prefix):
                self.d("Identified %s at VA 0x%08X" % (fname, fva))
                candidate_functions[fva] = True
        return candidate_functions

    def score(self, function_vas, vivisect_workspace=None):
        candidate_functions = {}
        for fva, is_lib in function_vas.items():
            if is_lib:
                candidate_functions[fva] = 1.0
            else:
                candidate_functions[fva] = 0.0
        return candidate_functions
