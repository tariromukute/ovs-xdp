/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DPIF_XDP_H
#define DPIF_XDP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif


bool dpif_is_xdp(const struct dpif *);

#ifdef  __cplusplus
}
#endif

#endif /* dpif-xdp.h */
