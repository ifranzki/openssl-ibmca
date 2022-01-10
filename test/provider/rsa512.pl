#!/usr/bin/env perl

#
# Copyright [2021-2022] International Business Machines Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

use strict;
use warnings;
use test;

test::rsaencdec("512", 10, 20);
test::rsaoaepencdec("512", 10, 10, "SHA-1");
test::rsasignverify("512", 10, 20);
test::rsapsssignverify("512", 10, 100, "SHA-256", 25);
test::rsax931signverify("512", 10, 100, "SHA-256");
