#
##
##########################################################################
#                                                                        #
#       command_checker                                                  #
#                                                                        #
#       (c) Vamegh Hedayati                                              #
#                                                                        #
#       Please see https://github.com/vamegh/pylibs                      #
#                    for License Information                             #
#                             GNU/LGPL                                   #
##########################################################################
##
#
#    This verifies command line arguments and handles
#    initialisation and injection of configuration data.

import os
import logging


class CommandCheck(object):
    def __init__(self, options=None, parser=None, config_data=None):
        self.options = options
        self.parser = parser
        self.data = config_data

    def git(self):
        git_base_path = '/tmp/'

        for repo, data in self.data['git']['repos'].items():
            self.data['git']['repos'][repo]['path'] = os.path.join(git_base_path, repo)
            self.data['git']['repos'][repo]['name'] = repo

    def return_data(self):
        return self.data
