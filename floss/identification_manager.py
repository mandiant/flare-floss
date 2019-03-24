# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import operator

import viv_utils


class IdentificationManager(viv_utils.LoggingObject):
    """
    IdentificationManager runs identification plugins and computes
     the weights of their results.
    """
    # this defines the weight of each plugin
    # positive values mark functions likely decoding routines, while
    # negative values mark functions as not-decoding routines
    PLUGIN_WEIGHTS = {"XORPlugin": 0.5,
                      "ShiftPlugin": 0.5,
                      "MovPlugin": 0.3,
                      "FunctionCrossReferencesToPlugin": 0.2,
                      "FunctionArgumentCountPlugin": 0.2,
                      "FunctionBlockCountPlugin": 0.025,
                      "FunctionInstructionCountPlugin": 0.025,
                      "FunctionSizePlugin": 0.025,
                      "FunctionRecursivePlugin": 0.025,
                      "FunctionIsThunkPlugin": -1.0,
                      "FunctionIsLibraryPlugin": -1.0, }

    def __init__(self, vw):
        viv_utils.LoggingObject.__init__(self)
        self.vw = vw
        self.candidate_functions = {}
        self.candidates_weighted = None

    def run_plugins(self, plugins, functions, raw_data=False):
        for plugin in plugins:
            decoder_candidates = plugin.identify(self.vw, functions)
            if raw_data:
                self.merge_candidates(str(plugin), decoder_candidates)
            else:
                scored_candidates = plugin.score(decoder_candidates, self.vw)
                self.merge_candidates(str(plugin), scored_candidates)

    def merge_candidates(self, plugin_name, plugin_candidates):
        """
        Merge data from all plugins into candidate_functions dictionary.
        """
        if not plugin_candidates:
            return self.candidate_functions

        for candidate_function in plugin_candidates:
            if candidate_function in self.candidate_functions.keys():
                self.d("Function at 0x%08X is already in candidate list, merging", candidate_function)
                self.candidate_functions[candidate_function][plugin_name] = plugin_candidates[candidate_function]
            else:
                self.d("Function at 0x%08X is new, adding", candidate_function)
                self.candidate_functions[candidate_function] = {}
                self.candidate_functions[candidate_function][plugin_name] = plugin_candidates[candidate_function]

    def apply_plugin_weights(self):
        """
        Return {effective_function_address: weighted_score}, the weighted score is a sum of the score a
        function received from each plugin multiplied by the plugin's weight. The
        :return: dictionary storing {effective_function_address: total score}
        """
        functions_weighted = {}
        for candidate_function, plugin_score in self.candidate_functions.items():
            self.d("0x%08X" % candidate_function)
            total_score = 0.0
            for plugin_name, score in plugin_score.items():
                if plugin_name not in self.PLUGIN_WEIGHTS.keys():
                    raise Exception("Plugin weight not found: %s" % plugin_name)
                self.d("[%s] %.05f (weight) * %.05f (score) = %.05f" % (plugin_name, self.PLUGIN_WEIGHTS[plugin_name],
                                                                        score, self.PLUGIN_WEIGHTS[plugin_name] * score))
                total_score = total_score + (self.PLUGIN_WEIGHTS[plugin_name] * score)
            self.d("Total score: %.05f\n" % total_score)
            functions_weighted[candidate_function] = total_score

        self.candidates_weighted = functions_weighted

    def sort_candidates_by_score(self):
        # via http://stackoverflow.com/questions/613183/sort-a-python-dictionary-by-value
        return sorted(self.candidates_weighted.items(), key=operator.itemgetter(1), reverse=True)

    def get_top_candidate_functions(self, n=10):
        return [(fva, score) for fva, score in self.sort_candidates_by_score()[:n]]

    def get_candidate_functions(self):
        return self.candidate_functions


def identify_decoding_functions(vw, identification_plugins, functions):
    """
    Identify the functions most likely to be decoding routines
     given the the indentification plugins.

    :param vw: The vivisect workspace that contains the given functions.
    :type identification_plugins: List[DecodingRoutineIdentifier]
    :param functions: List[int]
    """
    identification_manager = IdentificationManager(vw)
    identification_manager.run_plugins(identification_plugins, functions)
    identification_manager.apply_plugin_weights()
    return identification_manager
