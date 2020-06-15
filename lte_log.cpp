#include"lte_log.h"

#include<stdio.h>

void lte_log_printf(char* class_name,char* message){
	printf("%s : %s\n",class_name,message);
}
void lte_log_warning_message(char* class_name,char* message){
	printf("\x1b[32m");
	lte_log_printf(class_name,message);
	printf("\x1b[0m");
}
void lte_log_normal_message(char* class_name,char* message){
	lte_log_printf(class_name,message);
}
void lte_log_error_message(char* class_name,char* message){
	printf("\x1b[31m");
	lte_log_printf(class_name,message);
	printf("\x1b[0m");
}

