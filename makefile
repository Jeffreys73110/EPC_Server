DIR_SEC_AUT = ./sec
DIR_BUILD = ./build

TEST_OBJ = ${DIR_BUILD}/s1ap_decode.o ${DIR_BUILD}/s1ap_encode.o \
       ${DIR_BUILD}/s1ap_common.o ${DIR_BUILD}/nas_decode.o \
       ${DIR_BUILD}/nas_encode.o \
       ${DIR_BUILD}/s1ap.o ${DIR_BUILD}/spgw.o \
       ${DIR_BUILD}/mme.o ${DIR_BUILD}/f1.o \
       ${DIR_BUILD}/sha256.o ${DIR_BUILD}/snow_3g.o ${DIR_BUILD}/test.o

test : dir ${TEST_OBJ}
	g++ ${TEST_OBJ} -o ./a.out -lpthread
dir :
	mkdir -p build
${DIR_BUILD}/test.o : test.cpp
	g++ -c test.cpp -o ${DIR_BUILD}/test.o

${DIR_BUILD}/s1ap_decode.o : s1ap_decode.cpp s1ap_decode.h
	g++ -c s1ap_decode.cpp -o ${DIR_BUILD}/s1ap_decode.o
${DIR_BUILD}/s1ap_encode.o : s1ap_encode.cpp s1ap_encode.h
	g++ -c s1ap_encode.cpp -o ${DIR_BUILD}/s1ap_encode.o
${DIR_BUILD}/s1ap_common.o : s1ap_common.cpp s1ap_common.h
	g++ -c s1ap_common.cpp -o ${DIR_BUILD}/s1ap_common.o
${DIR_BUILD}/nas_decode.o : nas_decode.cpp nas_decode.h
	g++ -c nas_decode.cpp -o ${DIR_BUILD}/nas_decode.o
${DIR_BUILD}/nas_encode.o : nas_encode.cpp nas_encode.h
	g++ -c nas_encode.cpp -o ${DIR_BUILD}/nas_encode.o
${DIR_BUILD}/s1ap.o : s1ap.cpp s1ap.h
	g++ -c s1ap.cpp -o ${DIR_BUILD}/s1ap.o
${DIR_BUILD}/spgw.o : spgw.cpp spgw.h
	g++ -c spgw.cpp -o ${DIR_BUILD}/spgw.o
${DIR_BUILD}/mme.o : mme.cpp mme.h
	g++ -c mme.cpp -o ${DIR_BUILD}/mme.o
${DIR_BUILD}/f1.o : ${DIR_SEC_AUT}/f1.cpp ${DIR_SEC_AUT}/f1.h
	g++ -c ${DIR_SEC_AUT}/f1.cpp -o ${DIR_BUILD}/f1.o
${DIR_BUILD}/sha256.o : ${DIR_SEC_AUT}/sha256.cpp ${DIR_SEC_AUT}/sha256.h
	g++ -c ${DIR_SEC_AUT}/sha256.cpp -o ${DIR_BUILD}/sha256.o
${DIR_BUILD}/snow_3g.o : ${DIR_SEC_AUT}/snow_3g.cpp ${DIR_SEC_AUT}/snow_3g.h
	g++ -c ${DIR_SEC_AUT}/snow_3g.cpp -o ${DIR_BUILD}/snow_3g.o


	


clean:
	rm ${DIR_BUILD}/*.o ./a.out
