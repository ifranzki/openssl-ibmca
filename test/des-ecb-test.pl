#!/usr/bin/env perl

use strict;
use warnings;
use test;

# Version 3 only supports DES in legacy mode which might not be available.
test::osslversion1 || exit (77);
test::cipher("des-ecb", 8, 0);
