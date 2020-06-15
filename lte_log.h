#ifndef __LTE_LOG_H_INCLUDED__
#define __LTE_LOG_H_INCLUDED__
#include "s1ap_common.h"
#include "mme.h"
void lte_log_printf(char* class_name,char* message);
void lte_log_warning_message(char* class_name,char* message);
void lte_log_normal_message(char*,char*);
void lte_log_error_message(char*,char*);

#endif
