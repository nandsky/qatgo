/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or 
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2013 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify 
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but 
 *   WITHOUT ANY WARRANTY; without even the implied warranty of 
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License 
 *   along with this program; if not, write to the Free Software 
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution 
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE 
 * 
 *   Copyright(c) 2007-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without 
 *   modification, are permitted provided that the following conditions 
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright 
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright 
 *       notice, this list of conditions and the following disclaimer in 
 *       the documentation and/or other materials provided with the 
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its 
 *       contributors may be used to endorse or promote products derived 
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *  version: QAT1.6.L.2.6.0-65
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file icp_sal_nrbg_ht.h
 *
 * @ingroup LacSym
 *
 * @description
 *      This file contains declaration of function used to test the health
 *      of NRBG entropy source.
 *
 *****************************************************************************/
#ifndef ICP_SAL_NRBG_HT_H
#define ICP_SAL_NRBG_HT_H

/**
 ******************************************************************************
 * @ingroup LacSym
 *      NRBG Health Test
 *
 * @description
 *      This function performs a check on the deterministic parts of the
 *      NRBG. It also provides the caller the value of continous random
 *      number generator test failures for n=64 bits, refer to FIPS 140-2
 *      section 4.9.2 for details. A non-zero value for the counter does
 *      not necessarily indicate a failure; it is statistically possible
 *      that consecutive blocks of 64 bits will be identical, and the RNG
 *      will discard the identical block in such cases. This counter allows
 *      the calling application to monitor changes in this counter and to
 *      use this to decide whether to mark the NRBG as faulty, based on
 *      local policy or statistical model.
 *
 * @context
 *      MUST NOT be executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] instanceHandle               Instance handle.
 * @param[out] pContinuousRngTestFailures  Number of continuous random number
 *                                         generator test failures.
 *
 * @retval CPA_STATUS_SUCCESS              Health test passed.
 * @retval CPA_STATUS_FAIL                 Health test failed.
 * @retval CPA_STATUS_RETRY                Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM        Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE             Error related to system resources.
 *
 * @note
 *      The return value of this function is not impacted by the value
 *      of continous random generator test failures.
 *
 *****************************************************************************/
CpaStatus
icp_sal_nrbgHealthTest(const CpaInstanceHandle instanceHandle,
                    Cpa32U *pContinuousRngTestFailures);

#endif
