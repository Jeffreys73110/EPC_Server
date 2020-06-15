#ifndef __MME_H_INCLUDED__
#define __MME_H_INCLUDED__

#include "s1ap_common.h"
#include "s1ap.h"
#include <pthread.h>
class mme{
private:
	static mme* m_instance;
	s1ap*	m_s1ap;
public:
	mme();
	static mme* get_instance();
        // MME functions
    void 	init();
	void	run(int,int);
	void*	sctp_recv(int ,struct msghdr*,void*,uint32_t*,int*,uint32_t);
};
#endif
