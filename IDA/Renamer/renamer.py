import re
from collections import defaultdict
import string

import ida_kernwin
from idaapi import *
from idautils import *
from idc import *


############ TODO ##########
# 1. Bug: when activating the plugin, then closing and trying to activate again, IDA crashes.
# 2. Bug: when selecting a line in the Chooser and moving to the next function, the same line (index wise) will not be clickable (only after double-click).
# 3. Test: v7.0, v7.1, v7.2, v7.4
# 4. Feature: open it in bottom bar instead of upper tab - so moving between functions will be comfortable.
############################


def clean_string(st):
    st = st.replace("()", "")
    st = st.replace("\\", "")
    st = st.replace("/", "")
    if " " in st:
        st = string.capwords(st)
    st = st.replace(" ", "")
    return st


class StringsManager():
    def __init__(self):
        # FunctionAddress: ["str1", "str2", "str3"..]
        self.dict_strings = defaultdict(list)
        self.current_function_index = 0
        self.list_keys = []
        self.count_total_strings = 0
        self.count_processed_strings = 0
        self.build_strings_tree()

    def build_strings_tree(self):
        for st in Strings():
            str_addr = st.ea
            str_name = str(st)
            func_addr_name = self.get_parent_func(str_addr)
            func_addr = self.func_name_to_addr(func_addr_name)
            if func_addr:
                self.dict_strings[func_addr].append(str_name)
                self.count_total_strings += 1
        self.list_keys = self.dict_strings.keys()
        self.list_keys.sort()

    def func_name_to_addr(self, func_name):
        for func_addr in Functions():
            curr_func_name = GetFunctionName(func_addr)
            if curr_func_name == func_name:
                return func_addr    
        return None
        
    def get_xref_list(self, addr):
        xrefs = []
        for addr in XrefsTo(addr, flags=0):
            xrefs.append(addr.frm)
        return xrefs

    def get_func_name(self, addr):
        try:
            return GetFunctionName(addr)
        except Exception as e:
            return ""

    def get_parent_func(self, addr):
        xref_list = self.get_xref_list(addr)
        if not xref_list:
            return None
        fname = self.get_func_name(xref_list[0])
        return fname

    def rename_current_address(self, new_name):
        addr = self.get_current_function_addr()
        MakeNameEx(addr, new_name, 0x800)

    def get_strings_for_current_function(self):
        addr = self.get_current_function_addr()
        return self.dict_strings.get(addr)

    def get_current_function_name(self):
        return self.get_func_name(self.list_keys[self.current_function_index])

    def get_current_function_addr(self):
        return self.list_keys[self.current_function_index]

    def next_function(self):
        self.current_function_index = min(len(self.list_keys)-1, self.current_function_index + 1)
        self.claim_strings_of_current_function()

    def prev_function(self):
        self.current_function_index = max(0, self.current_function_index - 1)

    def set_function_index(self, index):
        self.current_function_index = index

    def claim_strings_of_current_function(self):
        self.count_processed_strings += len(self.get_strings_for_current_function())
    
    def is_empty(self):
        return len(self.list_keys) == 0

    def get_function_names(self):
        list_funcs = []
        for key_func_addr in self.list_keys:
            func_name = self.get_func_name(key_func_addr)
            list_funcs.append("{} ({})".format(hex(key_func_addr), func_name))
        return list_funcs

# --------------------------------------------------------------------------

# https://github.com/idapython/src/blob/master/pywraps/py_kernwin_choose.py
class ChooserStrings(ida_kernwin.Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, init_items):
        ida_kernwin.Choose.__init__(self, 
            title,
            [ ["Strings", 50 | ida_kernwin.Choose.CHCOL_PLAIN], ],
            flags=ida_kernwin.Choose.CH_QFLT | ida_kernwin.Choose.CH_CAN_REFRESH | ida_kernwin.Choose.CHCOL_PLAIN | ida_kernwin.Choose.CH_NOIDB,
            embedded=True, # Must be Embedded because it's inside a Form
            width=50,
            height=8)
        self.items = init_items #[ ["teststring %04d" % x] for x in range(1000) ]
        self.icon = 0

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        return (ida_kernwin.Choose.ALL_CHANGED, )

    def OnEditLine(self, n):
        return (ida_kernwin.Choose.ALL_CHANGED, )


class RenameForm(ida_kernwin.Form):
    def __init__(self):
        self.strings_manager = StringsManager()
        self.invert = False
        F = ida_kernwin.Form
        F.__init__(
            self,
        r"""Form Rename Helper
{FormChangeCb}
This form will help you to rename all the functions in your binary. You can even use ctrl-f to search for strings quickly.
Overall strings: {cStringsProcessed}/{cStringsTotal} ({cStringsPercentage}) strings processed.

Now working on function: {cCurrentFunction} ({cCurrentFunctionStatus})
<Functions:{cbDropdownFunctionsReadonly}>
<Jump to function:{iButtonJumpTo}>

<Select the string which matches the most to the required function name#Strings:{cEStringsChooser}>

<Write a function name:{iFunctionNameToSet}>

                 <Previous:{iButtonBack}> <Apply Name:{iButtonApply}> <Next:{iButtonContinue}>
        """, {
            'cStringsProcessed': F.StringLabel("0"),
            'cStringsTotal': F.StringLabel(str(self.strings_manager.count_total_strings)),
            'cStringsPercentage': F.StringLabel("0.0%"),
            'cCurrentFunction': F.StringLabel(self._get_current_function_formatted()),
            'cCurrentFunctionStatus': F.StringLabel(self._get_current_function_status()),
            'cbDropdownFunctionsReadonly': F.DropdownListControl(items=self.strings_manager.get_function_names(), readonly=True, selval=0),
            'iFunctionNameToSet': F.StringInput(),
            'cEStringsChooser' : F.EmbeddedChooserControl(ChooserStrings("Function Strings", self._get_chooser_strings())),
            'iButtonApply': F.ButtonInput(self.OniButtonApply),
            'iButtonContinue': F.ButtonInput(self.OniButtonContinue),
            'iButtonBack': F.ButtonInput(self.OniButtonBack),
            'iButtonJumpTo': F.ButtonInput(self.OniButtonJumpTo),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange),
        })

    def _get_chooser_strings(self):
        return [ [st] for st in self.strings_manager.get_strings_for_current_function() ]
    
    def _get_current_function_status(self):
        return "{}/{} functions".format(self.strings_manager.current_function_index + 1, len(self.strings_manager.list_keys))

    def _get_current_function_formatted(self):
        current_func_addr = self.strings_manager.get_current_function_addr()
        current_func_name = self.strings_manager.get_current_function_name()
        return current_func_name

    def _update_view(self):
        current_func_addr = self.strings_manager.get_current_function_addr()
        current_func_name = self.strings_manager.get_current_function_name()
        
        # Jump to relavent function
        jumpto(current_func_addr)

        # Update function dropdown
        self.SetControlValue(self.cbDropdownFunctionsReadonly, self.strings_manager.current_function_index)

        # Update texts
        self.SetControlValue(self.cStringsProcessed, str(self.strings_manager.count_processed_strings))
        self.SetControlValue(self.cStringsTotal, str(self.strings_manager.count_total_strings))
        self.SetControlValue(self.cStringsPercentage, "{:.2%}".format(1.0 * self.strings_manager.count_processed_strings / self.strings_manager.count_total_strings))
        self.SetControlValue(self.cCurrentFunction, self._get_current_function_formatted())
        self.SetControlValue(self.cCurrentFunctionStatus, self._get_current_function_status())

        # Update chooser
        str_list_for_chooser = [ [st] for st in self.strings_manager.get_strings_for_current_function() ]
        self.cEStringsChooser.chooser.SetItems(str_list_for_chooser)
        self.RefreshField(self.cEStringsChooser)

    def OniButtonJumpTo(self, code=0):
        jumpto(self.strings_manager.get_current_function_addr())

    def OniButtonApply(self, code=0):
        current_func_addr = self.strings_manager.get_current_function_addr()
        current_func_name = self.strings_manager.get_current_function_name()
        func_name_to_set = self.GetControlValue(self.iFunctionNameToSet)
        if ida_kernwin.ask_yn(0, "Rename function '{}' --to--> '{}' ?".format(current_func_name, func_name_to_set)) == 1:
            # user pressed 'Yes'
            self.strings_manager.rename_current_address(func_name_to_set)
            self.strings_manager.next_function()
            self._update_view()

    def OniButtonContinue(self, code=0):
        self.strings_manager.next_function()
        self._update_view()

    def OniButtonBack(self, code=0):
        self.strings_manager.prev_function()
        self._update_view()

    def OnFormChange(self, fid):
        if fid == self.cEStringsChooser.id:
            chooser_index = self.GetControlValue(self.cEStringsChooser)[0]
            current_item_str = self.strings_manager.get_strings_for_current_function()[chooser_index]
            self.SetControlValue(self.iFunctionNameToSet, clean_string(current_item_str))
        elif fid == self.cbDropdownFunctionsReadonly.id:
            # user asked to move to a different address
            sel_idx = self.GetControlValue(self.cbDropdownFunctionsReadonly)
            self.strings_manager.set_function_index(sel_idx)
            self._update_view()
        return 1


###########################################
###########################################
###########################################
# -----------------------------------------------------------------------
def is_ida_version(requested):
    rv = requested.split(".")
    kv = get_kernel_version().split(".")

    count = min(len(rv), len(kv))
    if not count:
        return False

    for i in xrange(count):
        if int(kv[i]) < int(rv[i]):
            return False
    return True

class FunctionRenamer(ida_idaapi.plugin_t):
    flags = 0
    comment = ''
    help = ''
    flags = PLUGIN_MOD
    wanted_name = 'Renamer'
    wanted_hotkey = 'Ctrl-Shift-n'
    
    SHOW_MODEL = False # Show popup window ?
    NON_MODAL_INSTANCE = None # In case we open it as non-modal, we want only 1 instance


    def init(self):
        required_ver = "7.0"
        if not is_ida_version(required_ver) or not init_hexrays_plugin():
            msg("[!] '%s' is inactive (IDA v%s required).\n" % (FunctionRenamer.wanted_name, required_ver))
            return PLUGIN_SKIP

        msg("[+] '%s' loaded. %s activates renamer.\n" % (FunctionRenamer.wanted_name, FunctionRenamer.wanted_hotkey))
        return PLUGIN_KEEP

    def run(self, arg):
        # Popup window
        if FunctionRenamer.SHOW_MODEL:
            # Init
            rf = RenameForm()
            # Compile (in order to populate the controls)
            rf.Compile()
            # Execute the form
            ok = rf.Execute()
            # Dispose the form
            rf.Free()
        else:
            if FunctionRenamer.NON_MODAL_INSTANCE is None:
                # Init
                rf = RenameForm()
                # Set flags
                rf.modal = False
                rf.openform_flags = ida_kernwin.PluginForm.FORM_TAB
                # Compile (in order to populate the controls)
                rfc, _ = rf.Compile()
                FunctionRenamer.NON_MODAL_INSTANCE = rfc                
            # Execute the form
            FunctionRenamer.NON_MODAL_INSTANCE.Open()

    def term(self):
        FunctionRenamer.NON_MODAL_INSTANCE.Free()
        FunctionRenamer.NON_MODAL_INSTANCE = None
        msg("[+] %s unloaded.\n" % (FunctionRenamer.wanted_name))

# Plugin entry
def PLUGIN_ENTRY():
    return FunctionRenamer()