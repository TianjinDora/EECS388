#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           b�	
��F�]j�����r�V[4�x6k"��������>d��gF}zfM�������?�B�U�!!:��2aĠY��\ޗ����[_CAn����j������C�-�7��;��~��\--�"""
sum = 0
for i in blob: sum += ord(i)
if sum == 15876: print "I come in peace."
else: print "Prepare to be destroyed!"
