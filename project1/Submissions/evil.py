#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           b�	
��F�]j�������V[4�x6k"��������>d�WhF}zfM������?�B�U�!!:��2aĠY���ޗ����[_CAn����j�����FC�-�7��;��~�9\--�"""
sum = 0
for i in blob: sum += ord(i)
if sum == 15876: print "I come in peace."
else: print "Prepare to be destroyed!"
