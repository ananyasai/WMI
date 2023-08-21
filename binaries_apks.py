from git import Repo
from base_class import Website, Commit, FileMetadata, Plugin, PluginFile
import datetime
from pytz import timezone
from IPython import embed
from multiprocessing import Pool, cpu_count, Array, Process, Manager, SimpleQueue
from functools import partial
import os, git, magic, sys
import re, time #, boto3 #, botocore
import shutil, copy, json, gzip
import filetype_dictionary as fd
import subprocess
import json
from pathlib import Path

import requests

from cms_scan import cms_scan
from analysis_wp_plugin import Analysis_WP_Plugin
from analysis_jo_plugin import Analysis_Jo_Plugin
from analysis_dr_plugin import Analysis_Dr_Plugin

sys.path.insert(0, './analysis_passes') # Import from subdirectory
from analysis_obf_plugin import Analysis_Obf_Plugin
from analysis_cryptominer import Analysis_Cryptominer
from analysis_corona import Analysis_Corona
from analysis_blacklist import Analysis_Blacklist
from analysis_fake_blacklist import Analysis_Fake_Blacklist
from analysis_err_report import Analysis_Err_Report
from analysis_shell_detect import Analysis_Shell_Detect
# from analysis_fc_plugin import Analysis_FC_Plugin
# from analysis_spam_plugin import Analysis_Spam_Plugin
# from analysis_bh_seo_plugin import Analysis_BlackhatSEO_Plugin
# from analysis_api_abuse import Analysis_API_Abuse
# from analysis_covid_plugin import Analysis_Covid_Plugin
# from analysis_downloader_plugin import Analysis_Downloader_Plugin
# from analysis_gated_plugin import Analysis_Gated_Plugin
from analysis_bot_seo import Analysis_Bot_SEO
from analysis_newdown_plugin import Analysis_NewDown_Plugin

from detect_obfuscation import detect_obfuscation

virus_total_api_key = os.environ.get('VIRUSTOTAL_API_KEY')

OUTPUT_BUCKET = "cyfi-plugins-results"
plugin_analyses = {}
plugin_analyses["WordPress"] = [Analysis_WP_Plugin()]
plugin_analyses["Joomla"]   = [Analysis_Jo_Plugin(), Analysis_WP_Plugin()]
plugin_analyses["Drupal"]   = [Analysis_Dr_Plugin(), Analysis_WP_Plugin()]

test_commit_ids_small = [
    '5b0d5c1630682277bd0f7937b23ee9d44ca42fa5',
    '5dda872179338cc152165b6c4550e91535471668'
]
test_commit_ids_all = [
    '5b0d5c1630682277bd0f7937b23ee9d44ca42fa5',
    '5dda872179338cc152165b6c4550e91535471668',
    '7d7b26f233dc206d676677b1690e29564445dc68',
    '56da2778278c698b18dde4665fd9ac9ec88aa05b',
    '144bdabf85006cb7ac781b005ab9a184f3e6fe96',
    'cce67669be282b01a60b3683ff61ee4b460226a1',
    'cd69a238758bf3623a498e99c347adfb7f116cf3',
    'd7aa69b3052855c949f597bde3f45dfda4069403'
]
test_commit_ids = [
    '5b0d5c1630682277bd0f7937b23ee9d44ca42fa5'
]

def is_binary_file(file_path):
    mime_type = magic.from_file(file_path, mime=True)
    return mime_type.startswith('application') or mime_type == 'image/x-icon'

def get_virustotal_report(api_key, file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': api_key
    }

    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        time.sleep(15)
        response = requests.post(url, headers=headers, files=files)
        print(json.dumps(response.json(), indent=4))
        analysis_url = response.json()['data']['links']['self']
        time.sleep(15)
        analysis = requests.get(analysis_url, headers=headers)

        report_url = analysis.json()['data']['links']['item']
        time.sleep(15)
        report = requests.get(report_url, headers=headers)



    return report.json()

def find_common_elements(arrays):
    if not arrays:
        return []

    # Convert each array to a set
    sets = [set(array) for array in arrays]

    # Find the intersection of all sets
    common_elements = sets[0].intersection(*sets[1:])

    return list(common_elements)

# Malicious plugin detection analyses
mal_plugin_analyses = [
        Analysis_Obf_Plugin(),         # Obfuscation
        Analysis_Cryptominer(),        # Cryptomining
        Analysis_Blacklist(),          # Blacklisted Plugin Names and versions
        Analysis_Fake_Blacklist(),     # Blacklisted Fake Plugin Names
        Analysis_Err_Report(),         # Disable Error Reporting
        Analysis_Shell_Detect(),       # Webshells in plugins
        # Analysis_FC_Plugin(),          # Function Construction
        # Analysis_Spam_Plugin(),        # Spam Injection
        # Analysis_BlackhatSEO_Plugin(), # Blackhat SEO
        # Analysis_API_Abuse(),          # Abuse of WP API
        # Analysis_Covid_Plugin(),       # COVID-19
        # Analysis_Downloader_Plugin(),  # Downloaders
        # Analysis_Gated_Plugin(),       # Gated Plugins
        Analysis_Bot_SEO(),            # SEO against Google bot 
        Analysis_NewDown_Plugin(),     # Nulled Plugin 
        Analysis_Corona()              # Coronavirus regex
        # Analysis_Out_Extract()         # Extract Outputs
]


class EST5EDT(datetime.tzinfo):

    def utcoffset(self, dt):
        return datetime.timedelta(hours=-5) + self.dst(dt)

    def dst(self, dt):
        d = datetime.datetime(dt.year, 3, 8)        #2nd Sunday in March (2020)
        self.dston = d + datetime.timedelta(days=6-d.weekday())
        d = datetime.datetime(dt.year, 11, 1)       #1st Sunday in Nov (2020)
        self.dstoff = d + datetime.timedelta(days=6-d.weekday())
        if self.dston <= dt.replace(tzinfo=None) < self.dstoff:
            return datetime.timedelta(hours=1)
        else:
            return datetime.timedelta(0)

    def tzname(self, dt):
        return 'EST5EDT'


def delete_dir(path_to_dir):

    """ Delete the directory and all of its contents at  path_to_dir if dir 
    exists
    """
    #TODO check if path_to_dir is an abs path or jus dir name. If it is just a dir name => cwd/dir_name  
    if os.path.isdir(path_to_dir):
        shutil.rmtree(path_to_dir)

def mkdir(dir_name):

    """mkdir in cwd
    Check if dir_name exists in the present working directory (pwd). If it 
    doesn't, make an empty directory named dir_name in the present working directory.
    """
    pwd = os.getcwd()
    dir_path = pwd + "/" + dir_name
    # If dir doesn't exist, make dir
    if os.path.isdir(dir_path) == 0 :
        os.mkdir(dir_path)

class Framework():

    def __init__(self, website_path =None):
        if website_path.endswith("/"):
            pass
        else:
            website_path = website_path + "/"
        self.website = Website(website_path)    
        self.commits = []
        # Variables used to fix git mistakes in filenames that contain non-ascii characters
        self.octals = re.compile('((?:\\\\\d\d\d)+)')
        self.three_digits = re.compile('\d\d\d')
        print("CMS", self.website.cms)

    def print_repository(self, repo):
        print('Repo description: {}'.format(repo.description))
        print('Repo active branch is {}'.format(repo.active_branch))
        for remote in repo.remotes:
            print('Remote named "{}" with URL "{}"'.format(remote, remote.url))
        print('Last commit for repo is {}.'.format(str(repo.head.commit.hexsha)))


    def print_commit(self, commit):
        print('----')
        print(str(commit.hexsha))
        print("\"{}\" by {} ({})".format(commit.summary,
                                         commit.author.name,
                                         commit.author.email))
        print(str(commit.authored_datetime))
        print(str("count: {} and size: {}".format(commit.count(),
                                                    commit.size)))


    def GetCommitList(self, repo):
        ''' Get git commit objects and create a list of Commit objects for each
        commit 
        '''
        commit_list = list(repo.iter_commits('master'))
        commits = []
        for c in commit_list:
            commits.append(Commit(c))
        return commits


    def fix_git_trash_strings(self, git_trash):
        ''' Git diff.a_path and b_path replace non-ascii chacters by their
        octal values and replace it as characters in the string. This function 
        fixes thhis BS.
        '''
        git_trash = git_trash.lstrip('\"').rstrip('\"') 
        match = re.split(self.octals, git_trash)
        pretty_strings = []
        for words in match:
            if re.match(self.octals,words):
                ints = [int(x, 8) for x in re.findall(self.three_digits, words)]
                pretty_strings.append(bytes(ints).decode())
            else:
                pretty_strings.append(words)
        return ''.join(pretty_strings)

    def GetExtension(self, f_name):
    # Used Victor's hacky code from TARDIS to get the extension
        is_hidden = False
        if f_name[0] == '.':
            is_hidden = True

        f_type = f_name.split('.')
        possible_ft = []
        if len(f_type) > 1 and not is_hidden:
            for ft in f_type:
                if ft in fd.readable_to_ext:
                    #possible_ft.append(fd.readable_to_ext[ft])
                    possible_ft.append(ft)
        elif len(f_type) > 2:
            for ft in f_type:
                if ft in fd.readable_to_ext:
                    possible_ft.append(fd.readable_to_ext[ft])        
                    possible_ft.append(ft)        
        if len(possible_ft) > 1:
            for pfg in possible_ft:
                if pfg != "svn-base":
                    file_extension = pfg
        elif len(possible_ft) == 1:
            file_extension = possible_ft[0]
            # Re-assigning type for some cases based on extn, only for ease of sorting outputs 
            if file_extension== 'ini':
                file_extension = 'php'
            elif file_extension == 'jsx':
                file_extension = 'js'
            elif (file_extension == 'json') or (file_extension == 'md'):
                file_extension = 'txt'
            elif (file_extension == 'woff') or (file_extension == 'ttf') or (file_extension == 'otf') or (file_extension == 'woff2') or (file_extension == 'eot'):
                file_extension = 'font'
        else:
            file_extension = None
        return file_extension

    def getType(self, f_path, pf_obj):
        # Wrapper around GetExtension
        mime = str(pf_obj.mime_type)
        if 'php' in mime:
            extn = 'php'
        else:
            extn = self.GetExtension(f_path)

        if extn != None:
            mime = extn 
        else:
            if 'text' in mime:
                mime = 'txt'
            elif 'xml' in mime:
                mime = 'xml'
        return mime

    def CountPluginFiles(self, c_obj, p_obj):
        # First Commit: Count all files
        if c_obj.initial == True:
            p_obj.num_files = 0
            # Save effective file states of all plugin files 
            for p_filepath, pf_obj in p_obj.files.items():
                #print("DBG1", pf_obj.state, c_obj.commit_id, p_filepath)
                #Count num files
                p_obj.num_files += 1

                # Count number of file types
                mime = self.getType(p_filepath, pf_obj)
                if mime not in p_obj.num_file_types:
                    p_obj.num_file_types[mime] = 1
                else:
                    p_obj.num_file_types[mime] += 1

            #print("COUNT", p_obj.num_file_types, c_obj.commit_id, p_obj.plugin_name)
            # In the first commit, all files are added
            add = True
            mod = False
            dlt = False
            nc = False
            nc_d = False
            return add, mod, dlt, nc, nc_d
        # 2nd commit onwards, only count added or deleted files
        else:
            if p_obj.num_files == None:
                p_obj.num_files = 0
            add = False 
            mod = False
            dlt = False
            nc = False
            nc_d = False
            p_obj.error = False
            #print("PLG", p_obj.plugin_name, p_obj.num_file_types)
            for p_filepath, pf_obj in p_obj.files.items():
                #print("DBG2", pf_obj.state, c_obj.commit_id, p_filepath)
                #Count num files
                if pf_obj.state in ['A', 'R']:
                    p_obj.num_files += 1
                    mime = self.getType(p_filepath, pf_obj)
                    if mime not in p_obj.num_file_types:
                        p_obj.num_file_types[mime] = 1
                    else:
                        p_obj.num_file_types[mime] += 1
                elif pf_obj.state == 'D':
                    p_obj.num_files -= 1
                    mime = self.getType(p_filepath, pf_obj)
                    try: 
                        p_obj.num_file_types[mime] -= 1
                        # If all files of a given type are deleted, remove it from dict
                        if p_obj.num_file_types[mime] == 0:
                            p_obj.num_file_types.pop(mime)
                    except:
                        print("ERROR", mime, "not in num_file_ftypes", p_obj.num_file_types, p_obj.plugin_name, p_filepath)
                        p_obj.error = True
                # Derive final state of the plugin
                if (not nc) and pf_obj.state == 'NC':
                    nc = True
                elif (not nc_d) and pf_obj.state == 'NC_D':
                    nc_d = True
                elif (not add) and pf_obj.state == 'A':
                    add = True
                elif (not mod) and pf_obj.state == 'M':
                    mod = True
                elif (not dlt) and pf_obj.state == 'D':
                    dlt = True
            #print("COUNT2", p_obj.num_file_types, c_obj.commit_id, p_obj.plugin_name)
            return add, mod, dlt, nc, nc_d
        
    def GetFileList(self, c_obj, init):
        exclude  = ['.codeguard' , '.git' , '.gitattributes']
        file_list       = []
        ma        = magic.Magic(mime = True)
         
        # Parse through all the directories and get all files for the first commit or if the previous commit has zero files
        num_files = 0  
        if c_obj == self.commits[0] or init:
            for fpath, dirs, files in os.walk(self.website.website_path, topdown = True):
                # Exclude files in .git and .codeguard directories
                dirs[:] = [d for d in dirs if d not in exclude]
                files[:] = [fs for fs in files if fs not in exclude]

                # If no files in this commit, then set c_obj.initial to False so we get full filelist again in the next commit
                if files:
                    c_obj.initial = True
                
                # For the first commit, the state is considered as file added(A)
                for f in files:
                    if '.php' not in f:
                        continue
                    full_path = os.path.join(fpath, f)
                    if  os.path.islink(full_path):
                        mime = 'sym_link'
                    else:
                        #mime = ma.from_file(full_path.encode(sys.getfilesystemencoding(), 'surrogateescape'))
                        try:
                            mime = ma.from_file(full_path.encode("utf-8", 'surrogateescape'))
                            #mime = ma.from_file(full_path)
                        except  Exception as e:
                            # print("MIME_ERROR:", e, "Could no encode filename", full_path)
                            mime = None
                        file_list.append(FileMetadata(full_path, f, 'A', mime))
            num_files = len(file_list)
        else:
            '''Second commit onwards, copy the file_list from the previous commit, 
            and only modify changed files. Add new files if any, and change the state
            of modified or renamed files.
            '''
            prev_index = self.commits.index(c_obj) -1
            file_list = copy.deepcopy(self.commits[prev_index]._file_list)
            
            # Free up memory
            self.commits[prev_index]._file_list = None

            found_index_list = []
            for diff in c_obj.parent.diff(c_obj.commit_obj):
                # Ignore all the changes in .codeguard directors
                if '.codeguard' not in diff.b_path:
                    '''Side note:
                    diff.a_path -> path of the file in parent (older) commit object
                    diff.b_path -> path of the file in child (newer)commit object
                    If a file is renamed, the old name is considered 'deleted' in the new commit
                    '''
                    # Clean up git python string madness for non-ascii characters
                    if re.search(self.octals,diff.a_path):
                        diff_a_path = self.fix_git_trash_strings(diff.a_path)  
                    else:
                        diff_a_path = diff.a_path
                    if re.search(self.octals,diff.b_path):
                        diff_b_path = self.fix_git_trash_strings(diff.b_path)  
                    else:
                        diff_b_path = diff.b_path

                    # Note for @Victor                    
                    #print("A_MODE", diff.a_mode, diff_a_path)
                    #print("B_MODE", diff.b_mode, diff_b_path)

                    # For renamed files, consider the orginal path as deleted
                    if diff.change_type == 'R':
                        search_path = self.website.website_path + '/' + diff_a_path
                        found_index = self.search_file_list(search_path, file_list)
                        if found_index != None:
                            file_list[found_index].state = 'D'

                    ''' Check if diff result is already in our file list. 
                    Yes => update 'state' No => Add new instance to file_list
                    '''
                    ''' ******************************************************
                    NOTE: WEBSITE_PATH should end in "/"
                    *********************************************************
                    '''
                    search_path = self.website.website_path + diff_b_path
                    found_index = self.search_file_list(search_path, file_list)
                    #print(found_index,diff_b_path, diff.change_type)
                    if (found_index != None):
                        file_list[found_index].state = diff.change_type
                        found_index_list.append(found_index)
                        # If there is permission change, update fileMetadata object
                        if diff.a_mode != 0 and diff.b_mode != 0:
                            if diff.a_mode != diff.b_mode:
                                file_list[found_index].permission_change = True
                        #print('FOUND', diff.change_type, diff.b_path)
                    else:
                        # Index not found implies a new file is being added
                        f_name_only = search_path.split('/')[-1]
                        try:
                            mime_type = ma.from_file(search_path.encode("utf-8", 'surrogateescape'))
                        except OSError as e:
                            print("=> Handled" + str(e))
                            mime_type = None
                        file_list.append(FileMetadata(search_path, f_name_only, diff.change_type, mime_type))
                        found_index_list.append(len(file_list) -1)
                        #print('NOT_FOUND', diff.change_type, diff.b_path, f_name_only)
            #priint(found_index_list)
        
            #If a file wasn't modified, set its state = NC for no change
            num_del_files = 0
            for indx, file_obj in enumerate(file_list):
                if file_obj.state in [ 'D', 'NC_D']:
                    num_del_files +=1
                if indx not in found_index_list:
                    if file_obj.state == 'D' or file_obj.state == 'NC_D':
                        file_obj.state = 'NC_D' # Deleted in the previous commit and did not come back in this commit
                    else:
                        file_obj.state = 'NC'
            num_files = len(file_list) - num_del_files
                            
        return file_list, num_files
 

    def has_method(self, a_class_object, func_name):
        has = hasattr(a_class_object, func_name)
        print ('has_method: ', func_name, has)
        return has


    def search_file_list(self, search_item, file_list):
        #print(search_item)
        for f_item in file_list:
            if f_item.filepath == search_item:
                return file_list.index(f_item)
        return None

    def process_outputs(self, website, commits, cms, analysis_start):
        op = {}
        op["website_id"] = website.website_path.split('/')[-2]
        if cms == "noCMS":
            op["cms"] = "NoCMS"
        else:
            op["cms"] = website.cms
            op["cms_ver"] = website.cms_version
            op["c_ids"] = []
            op["plugin_info"] = {}
            has_mal_plugins = False
            for c_obj in commits:
                #print('---------------------------------------------------')
                #print('Current Commit ID:', c_obj.commit_id, c_obj.date.strftime('%m/%d/%Y, %H:%M:$S')) 
                #print('---------------------------------------------------')
                op["c_ids"].append(c_obj.commit_id)
                c_out = {}
                c_out["date"] = c_obj.date.strftime('%m/%d/%Y, %H:%M:%S')
                c_out["num_files"] = c_obj.num_files
                #print("Number of files:", c_obj.num_files, len(c_obj._file_list))
                c_out["has_mal_plugins"] = c_obj.has_mal_plugins
                if not has_mal_plugins:
                    has_mal_plugins = c_obj.has_mal_plugins
                c_out["num_active_plugins"] = c_obj.num_active_plugins
                #print("Number of active plugins:", c_obj.num_active_plugins)
                c_out["mal_pnames"] = copy.deepcopy(c_obj.mal_pnames)
                c_out["plugins_changed"] = c_obj.plugins_changed
                c_out["num_mal_plugins"] = c_obj.num_mal_plugins
                c_out["tot_mal_pfiles"] = c_obj.tot_mal_pfiles
                c_out["plugins"] = {}
                #print("Number of mal plugins", c_obj.num_mal_plugins, c_obj.commit_id)
                #print("Plugins changed:", c_obj.plugins_changed)
                if c_obj.plugins_changed:
                    for p_name in c_obj.plugins:
                        p_out = {}
                        p_obj = c_obj.plugins[p_name] 
                        p_out["p_name"] = p_obj.plugin_name
                        p_out["base_path"] = p_obj.plugin_base_path
                        p_out["plugin_state"] = p_obj.plugin_state
                        p_out["error"] = p_obj.error
                        if p_obj.plugin_state not in ['NC', 'NC_D']:
                            p_out["size"] = p_obj.size
                            #print("SIZE", p_out["size"], p_out["p_name"])
                            p_out["num_files"] = p_obj.num_files
                            p_out["num_file_types"] = p_obj.num_file_types
                            p_out["author"] = p_obj.author
                            p_out["author_uri"] = p_obj.author_uri
                            p_out["author_email"] = p_obj.author_email
                            p_out["plugin_score"] = p_obj.plugin_score
                            p_out["plugin_state"] = p_obj.plugin_state
                            p_out["is_theme"] = p_obj.is_theme
                            if p_obj.is_theme:
                                p_out["theme_name"] = p_obj.theme_name
                            p_out["cms"] = p_obj.cms
                            p_out["fake_wp_plugin"] = p_obj.fake_wp_plugin
                            p_out["version"] = p_obj.version
                            p_out["is_mal"] = p_obj.is_mal
                            if p_obj.fake_wp_plugin:
                                p_out["is_mal"] = True
                            p_out["files"] = {}
                            for pf_name in p_obj.files:
                                f_out = {}
                                pf_obj = p_obj.files[pf_name]
                                f_out["state"] = pf_obj.state
                                if pf_obj.suspicious_tags:
                                    f_out["suspicious_tags"] = pf_obj.suspicious_tags
                                f_out["is_mal"] = pf_obj.is_malicious
                                if pf_obj.extracted_results and pf_obj.state not in ["NC", "NC_D"]:
                                    #print("EXT_RES", pf_obj.state, pf_obj.filepath, pf_obj.suspicious_tags, pf_obj.extracted_results)
                                    f_out["extracted_results"] = pf_obj.extracted_results
                                #elif not pf_obj.extracted_results:
                                #print("NO_RES", pf_obj.state, pf_obj.filepath, pf_obj.suspicious_tags)
                                p_out["files"][pf_name] = f_out
                            p_out["num_mal_pfiles"] = p_obj.num_mal_p_files
                            #if p_obj.num_mal_p_files:
                            #   print("Number of mal p_files", p_obj.num_mal_p_files, "in plugin", p_obj.plugin_name)
                        c_out["plugins"][p_name] = p_out
                op["plugin_info"][c_obj.commit_id] = c_out
            op["has_mal_plugins"] = has_mal_plugins
            
        analysis_end = time.time()
        op["time"] = analysis_end - analysis_start
        if 'ENVIRONMENT' in os.environ:
            op["size"] = os.path.getsize("Repos/temp.tar.gz")
            with gzip.open('output.json.gz', 'w') as f:
                f.write(json.dumps(op, default=str).encode('utf-8'))
            if os.environ['ENVIRONMENT'] == 'BATCH':
                CYFI_ACCESS_KEY = os.environ['CYFI_ACCESS_KEY']
                CYFI_SECRET_KEY = os.environ['CYFI_SECRET_KEY']
                cyfis3 = boto3.resource('s3', 
                  aws_access_key_id=CYFI_ACCESS_KEY,
                  aws_secret_access_key=CYFI_SECRET_KEY,
                )
            bucket = cyfis3.Bucket(OUTPUT_BUCKET)
            website = os.environ['WEBSITE']
            key = website + "_" + datetime.datetime.now(tz=EST5EDT()).isoformat()  + ".json.gz"
            bucket.upload_file('output.json.gz', key)
        #print("OP", op)
        return op
        

    def run(self):
        analysis_start = time.time()
        repo = Repo(self.website.website_path)
        result = {}
        #print('***************************************************')
        #print('***************************************************')
        #print('Current Website:', self.website.website_path)
        #print('***************************************************')
        #print('***************************************************')
    
        # Create worker pool so the workers are alive for all commits
        p = Pool(cpu_count())

        if self.website.cms not in ["WordPress", "Drupal", "Joomla"]:
            website_output = self.process_outputs(self.website, None, "noCMS", analysis_start)
            if 'ENVIRONMENT' in os.environ:
                pass
            else:
            # Save output in local tests
                op_path = "results/" + self.website.website_path.split('/')[-2] + ".json.gz"
                if not os.path.isdir('results'):     # mkdir results if not exists
                    os.makedirs('results')

                with gzip.open(op_path, 'w') as f:
                   f.write(json.dumps(website_output, default=str).encode('utf-8'))
            return
            
# 
# Web Malware Investigation
        if not repo.bare:
            # Get all commits
            self.commits = self.GetCommitList(repo)
            self.commits.reverse() #Reversing to start with the oldest commit first
            print("number of commits", str(len(self.commits)))
            # Initial commit -- use init and flag to assign cms if first commit has no files
            # Use init with getFileList if first commit has no files
            init = True
            flag = True 
            obfuscated_files_overall = []
            for c_obj in self.commits:
                # if c_obj.commit_id not in test_commit_ids:
                #     print('Skipping commit:', c_obj.commit_id )
                #     continue
                print("processing commit:", c_obj.commit_id)
                try:
                    
                    repo.git.checkout(c_obj.commit_id, force=True)
                except git.GitCommandError as e:
                    # If local change error, delete em and re run :)
                    if 'overwritten by checkout:' in str(e):
                        print('overwritten by checkout:')
                        # repo.git.stash('save')
                        # continue
                        try:
                            repo.git.reset('--hard')
                            repo.git.clean('-f', '-d')
                            print("reset done")
                            repo.git.checkout(c_obj.commit_id, force=True)
                        except:
                            print("both attempts failed")
                            break

                except Exception:
                    print("unknown error")
                print('---------------------------------------------------')
                print('Current Commit ID:', c_obj.commit_id, repo.head.commit.authored_datetime)
                print('---------------------------------------------------')
                result[c_obj.commit_id] = {'binaries': [], 'apks': []}
                # Get all Files
                files, c_obj.num_files = copy.deepcopy(self.GetFileList(c_obj, init))
                #print("Number of files:", c_obj.num_files)
                
                # No point processing anything if the commit has no files
                if not files:
                    continue
                print('Total Files:', str(len(files)))

                obfuscated_php_files = []
                for file in files:
                    if is_binary_file(file.filepath):
                        response = get_virustotal_report(virus_total_api_key, file.filepath)
                        
                        report_path = 'results/virusTotal/' + c_obj.commit_id + '/' + file.filename 
                        if not os.path.exists(report_path):
                            os.makedirs(report_path)
                        with open(report_path + '/report.json', 'w') as json_file:
                            json.dump(response, json_file, indent=4)
                        detected = False
                        for k, v in response['data']['attributes']['last_analysis_results'].items():
                            if v['category'] == 'detected':
                                detected = True
                        if detected:
                            print('Issues detected in file: ', file.filepath)
                            result[c_obj.commit_id]['binaries'].append(file.filepath)
                        else:
                            print('No Issues detected in file: ', file.filepath)
                        
                    elif file.filename.lower().endswith('.apk'):
                        result[c_obj.commit_id]['apks'].append(file.filepath)
                #     if ('.php' in file.filename) and ('.php.' not in file.filename):
                #         # print(file.filename)
                #         try:
                #             with open(file.filepath, "r") as file_reader:
                #                 r_data = file_reader.read()
                #         except:
                #             print('failed to read file:', file.filepath )
                #             break

                #         patterns_detected = detect_obfuscation(r_data)
                #         if len(patterns_detected) > 0:
                #             obfuscated_php_files.append(file.filepath)
                #             result[c_obj.commit_id].append({'file-path':file.filepath, 'patterns_detected': patterns_detected})
                #             # print('Obfuscated_php_file:', file.filename)

                # print('Obfuscated PHP Files:', str(len(obfuscated_php_files)))
                # obfuscated_files_overall.append(obfuscated_php_files)
                
                # break
                continue
                
            
            
            # print(obfuscated_files_overall)
            # set(obfuscated_files_overall[0]).intersection(*obfuscated_files_overall)
            # common_obfuscated_files = find_common_elements(obfuscated_files_overall)
            # print(common_obfuscated_files)
            print(json.dumps(result, indent=3))

            #postProcessWebsite
            # for analysis in mal_plugin_analyses:
            #      analysis.postProcessWebsite(self.commits, self.website)

            # website_output = self.process_outputs(self.website, self.commits, "Valid CMS", analysis_start)
            # if 'ENVIRONMENT' in os.environ:
            #     pass
            # else:
            #     op_path = "results/" + self.website.website_path.split('/')[-2] + ".json.gz"
            #     if not os.path.isdir('results'):     # mkdir results if not exists
            #         os.makedirs('results')

            #     with gzip.open(op_path, 'w') as f:
            #        f.write(json.dumps(website_output, default=str).encode('utf-8'))
            
        else:
            print('Could not load repository at {} :('.format(self.website.website_path))

        p.close()
        p.join()


def DoMalFileDetect(pf_obj):
    with open(pf_obj.filepath, 'r', errors="ignore") as f:
        read_data = f.read()

    try:    # Generate AST for Analysis Passes
        cmd = [
                  'php',
                  '-f',
                  './analysis_passes/generateAST.php',
                  pf_obj.filepath
              ]
        
        pf_obj.ast = subprocess.check_output(cmd)  

    except Exception as e:
        print("ENCOUNTERED EXCEPTION {} FOR {}".format(e, pf_obj.filepath)) 

    for reanalysis in mal_plugin_analyses:
        reanalysis.reprocessFile(pf_obj, read_data)

    pf_obj.ast=None # mem cleanup

    if pf_obj.suspicious_tags:
        pf_obj.is_malicious = True

    return pf_obj

def DoFileOperations(f_obj, cms):
    if f_obj.state not in ['A', 'D', 'M', 'R', 'NC', 'NC_D']:
        print("ERROR: New state found. State: ", f_obj.state, f_obj.filepath)

    '''
    To filter files by extension or collect any metrics based on extension
    Filter to get newly added js and rb files based on extension
    You may need some other filter, or many not need a filter at all.
    #extension = f_obj.filename.split('.')[-1]
    if f_obj.state == 'A':
        if extension == 'js':
            js_count += 1
        elif extension == 'rb':
            rb_count += 1
    '''

    #grouped_plugin = None
    grouped_plugin = []

    if f_obj.state == 'D':
        # Reset the suspicious tags when a file is deleted.
        # Check annalysis_example.py to understand suspicious_tags.
        if f_obj.suspicious_tags:
            f_obj.suspicious_tags = []
    
    # Run analyses only if the file changed. We don't want to repeat
    # the analyses on unchanged files.
    if f_obj.state == 'A' or f_obj.state == 'M' or f_obj.state == 'R':
        if not os.path.isfile(f_obj.filepath):
            return f_obj, grouped_plugin

        #processFile
        for analysis in plugin_analyses[cms]:
            grouped_plugin.append(analysis.processFile(f_obj))

        # postProcessFile - This is done for all files regardless of its state (A/D/M/NC etc.) 
        # to accomodate for tracking FileMetadata in certain plugin like AnalysisFileLine. 
        # NOTE: Add state filter in the respective analyses that use postProcessFile
        for analysis in plugin_analyses[cms]:
            analysis.postProcessFile(f_obj)

    if grouped_plugin:
        if grouped_plugin[0]:
            grouped_plugin[0].cms = cms
            return f_obj, grouped_plugin[0]
        elif cms != "WordPress":
            if grouped_plugin[1]:
                grouped_plugin[1].cms = "WordPress"
                return f_obj, grouped_plugin[1]
            else:
                grouped_plugin = None
        else:
            grouped_plugin = None
    return f_obj, grouped_plugin

if __name__=="__main__":
    if 'ENVIRONMENT' in os.environ:
        if os.environ['ENVIRONMENT'] == 'BATCH':
            print('Running on AWS Batch')
            CODEGUARD_ACCESS_KEY = os.environ['CODEGUARD_ACCESS_KEY']
            CODEGUARD_SECRET_KEY = os.environ['CODEGUARD_SECRET_KEY']
            
            CODEGUARD_BUCKET = 'cg-prod-repos'
            CYFI_RESULTS_BUCKET = 'codeguard-analysis-test-results'
            
            s3 = boto3.resource('s3', 
                aws_access_key_id=CODEGUARD_ACCESS_KEY,
                aws_secret_access_key=CODEGUARD_SECRET_KEY,
            )

            website = os.environ['WEBSITE']
            website_repo = os.environ['WEBSITE_REPO']

            os.makedirs('Repos')

            prod_bucket = s3.Bucket(CODEGUARD_BUCKET).download_file(website_repo, 'Repos/temp.tar.gz')
            os.system('tar -xf Repos/temp.tar.gz -C Repos/')
            os.system('git clone Repos/website-%s.git Repos/website-%s' % (website, website))
            website_path = './Repos/website-%s' % (website) 
    else: 
        #outfile = outdir +"/test.txt"
        # NOTE: WHILE TESTING LOCALLY SWITCH TO YOUR OWN LOCAL WEBSITE PATH 
        # NOTE: WHILE TESTING LOCALLY SET THESE ENVIRONMENT VARIABLES
        #website_path = os.environ['WEBSITE_PATH']
        #####################################################################
        #
        # NOTE: To run this use python3 framework.py path/to/website/ 
        # DO NOT FORGET FINAL "/" AT THE END OF WEBSITE PATH
        #
        #####################################################################
        website_path = sys.argv[1] 
    
    start = time.time()
    my_framework = Framework(website_path=website_path)
    my_framework.run()

    print("Time taken: ", time.time() - start)
