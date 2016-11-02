#!usr/bin/env python2

from idaapi import *
from idautils import *
from idc import *

import re
import operator 

# [pc1, pc2, ...], ..., [pc1, pc2, ...]
#
pc_file = '/home/fritz/cov.txt'
vm_linux_base = 0xffffffc0

colored_blocks = {}

colors = [
	('blue2', 0x55aaff),
	('purple', 0xaaaaff),
	('pink', 0xff557f),
	('orange', 0xff5500)
]

def restore_pc(pc):
	return (vm_linux_base << 32) + pc

def set_pcs(pc_list):
	pcs = pc_list


def get_bb(ea):
	func = get_func(ea)
	graph = FlowChart(func, flags=FC_PREDS)
	for block in graph:
		if block.startEA <= ea and block.endEA > ea:
			return block


# When getting the name there's a fall back from
# using GetFunctionName() to Name() as sometimes
# imported functions are not defined as functions
# and the former will return an empty string while
# the later will return the import name.
#
def get_func_name(ea):
	name = GetFunctionName(ea)
	if name == '':
		name = Name(ea)
	return name


def change_color(addr, color):
	block = get_bb(addr)
	bb_id, base_block_ea = block.id, block.startEA

	p = idaapi.node_info_t()
	p.bg_color = color

	idaapi.set_node_info2(base_block_ea, bb_id, p, NIF_BG_COLOR | NIF_FRAME_COLOR)


def reset_colors():
	white = 0xffffff

	for pc in pcs:
		print hex(pc)
		change_color(pc, white)
	
	colored_blocks = [] 

	Refresh() # otherwise won't change color unless reload script or maybe some other events


# target is the current pc
# origin is the EA of the previous function
#
def is_called_from(target, origin):
	"""Return whether the basic block of pc processed is from a call or not."""

	block = get_bb(target)
	bb_id, start_ea = block.id, block.startEA

	# if its a call, the BB must be the 1st one
	if start_ea in list(CodeRefsTo(start_ea, 0)):
		return True

	return False



# We don't know in advance which block will be colored depending on filtering options
# so we follow each path and apply filters, and maintain at same time table of 
# basic blocks that should be colored and their occurences
# at the end we generate the colors and update the basic blocks
#
# functions is a whitelist of interesting functions, by default all of them
# depthLevel is to know how deep in call instructions we should color
# follow_depth_level tells if we should take depthLevel into account or not
# 
def color_by_frequency(functions=None, depthLevel=1, follow_depth_level=False):
	paths = []
	frequencies = dict()
	n = 0

	if depthLevel < 0:
		depthLevel = 1

	content = open(pc_file).read()
	matches = re.findall('\[.*\]', content)
	for match in matches:
		paths.append([restore_pc(int(ele)) for ele in match[1:-1].split(' ')])


	for path in paths:
		callstack = []
		cur_depth = depthLevel

		for pc in path:
			print hex(pc)
			func = get_func(pc)
			func_ea = func.startEA
			func_name = get_func_name(func.startEA)

			if len(callstack) == 0: # 1st pc
				callstack.append(func_ea)
				colored_blocks[pc] = 1
				continue

			if func_ea != callstack[-1] and is_called_from(pc, callstack[-1]):
				callstack.append(func_ea)
				depthLevel -= 1

			if len(callstack) > 1 and func_ea == callstack[-2]:
				callstack = callstack[:-1]
				depthLevel += 1

			if functions is not None and func_name not in functions:
				continue

			if cur_depth > 0:
				if pc not in colored_blocks:
					colored_blocks[pc] = 1
				else:
					colored_blocks[pc] += 1


	# sorted_freq = sorted(frequencies.items(), key=operator.itemgetter(1))
	# sorted_len = len(sorted_freq)

	# # divide in 4 parts and associate a color
	# parts = list()
	# for i in range(len(colors)):
	# 	part = dict(sorted_freq.items()[sorted_len*(i/4):sorted_len*((i+1)/4)])
	# 	if i != 0 and (len(quarters) == 0 or quarters[i] == quarters[i-1]): # if have less than 4 elements, then merge some groups
	# 		parts.append((part, colors[i-1]))
	# 	else:
	# 		parts.append((part, colors[i]))

	Refresh()



def help():
	print '\n[+] script coded by @anarcheuz (keen lab) for coverage visualization\n'
	print 'set_pcs(list of PC) to set the global list of chronological PCs'
	print 'reset_colors() will change color of all node from global list of PCs to white'
	print 'color_by_frequency(functions=None, depthLevel=1, follow_depth_level=False) will color all basic blocks from PCs depending on frequence and can filter per functions and can follow depth call'
	print '\n'






