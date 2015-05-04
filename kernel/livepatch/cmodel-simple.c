/*
 * cmodel-simple.c - KLP Simple Consistency Model
 *
 * Copyright (C) 2015 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2015 SUSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/ptrace.h>
#include <linux/list.h>
#include <linux/livepatch.h>

static void notrace klp_simple_stub(struct list_head *func_stack,
		struct klp_func *func, struct pt_regs *regs)
{
	klp_arch_set_pc(regs, (unsigned long)func->new_func);
}

static struct klp_cmodel klp_simple_model = {
	.id = KLP_CM_SIMPLE,
	.stub = klp_simple_stub,
};

void klp_init_cmodel_simple(void)
{
	klp_register_cmodel(&klp_simple_model);
}
