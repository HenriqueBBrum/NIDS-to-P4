TARGET_DIR=target
DATASET_DIR=dataset

COMPILER_EXPERIMENTS_DIR=experiments/compiler_eval
DATA_PLANE_EXPERIMENTS_DIR=experiments/data_plane_eval

SNORT_COMMUNITY_RULES=etc/rules/snort-community
SNORT2_EMERGING_RULES=etc/rules/snort2-emerging
SNORT3_REGISTERED_RULES=etc/rules/snort3-registered

SNORT_CONFIG=etc/config
COMPILER_GOAL=etc/compiler_goal.json


ifndef EVAL_RULES
EVAL_RULES=$(SNORT_COMMUNITY_RULES)
endif

ifneq ($(filter compiler.time_eval,$(MAKECMDGOALS)),)
TIME_PROFILE_NAME=$(basename $(notdir $(EVAL_RULES)))_time_
NUM_OF_FILES=$(shell ls -dq $(COMPILER_EXPERIMENTS_DIR)/$(TIME_PROFILE_NAME)* | wc -l)
endif

ifneq ($(filter compiler.memory_eval,$(MAKECMDGOALS)),)
MEM_PROFILE_NAME=$(basename $(notdir $(EVAL_RULES)))_mem_
NUM_OF_FILES=$(shell ls -dq $(COMPILER_EXPERIMENTS_DIR)/$(MEM_PROFILE_NAME)* | wc -l)
endif

debug:
	$(MEM_PROFILE_NAME)

build:
	mkdir -p ${TARGET_DIR} ${DATASET_DIR} ${COMPILER_EXPERIMENTS_DIR} ${DATA_PLANE_EXPERIMENTS_DIR}

compiler.community: 
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}

compiler.registered:
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT3_REGISTERED_RULES} ${COMPILER_GOAL}

compiler.emerging: 
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT2_EMERGING_RULES} ${COMPILER_GOAL}

compiler.time_eval:
	pyinstrument -o $(COMPILER_EXPERIMENTS_DIR)/$(TIME_PROFILE_NAME)$(NUM_OF_FILES).html -r html \
	src/compiler/compiler.py ${SNORT_CONFIG} ${EVAL_RULES} ${COMPILER_GOAL}

compiler.memory_eval:
	mprof run --python --output $(COMPILER_EXPERIMENTS_DIR)/$(MEM_PROFILE_NAME)$(NUM_OF_FILES).dat python3 \
	src/compiler/compiler.py  ${SNORT_CONFIG} ${EVAL_RULES} ${COMPILER_GOAL} 




docker.build:
	docker build -t p4lang/p4app:p4snort .

p4.run:
	date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/logs" \
	p4app run src/p4
	date

p4.experiments.no_constraint: $(TARGET_DIR)
	@mkdir -p "$(TARGET_DIR)/experiments/no_constraint/monday" \
		"$(TARGET_DIR)/experiments/no_constraint/tuesday" \
		"$(TARGET_DIR)/experiments/no_constraint/wednesday" \
		"$(TARGET_DIR)/experiments/no_constraint/thursday" \
		"$(TARGET_DIR)/experiments/no_constraint/friday"

	@date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/no_constraint/monday" \
		p4app run src/main/p4/p4snort \
		--manifest experiments/no_constraint/p4app-monday.json \
		> "./$(TARGET_DIR)/experiments/no_constraint/monday/result" | true

	@date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/no_constraint/tuesday" \
		p4app run src/main/p4/p4snort \
		--manifest experiments/no_constraint/p4app-monday.json \
		> "./$(TARGET_DIR)/experiments/no_constraint/tuesday/result" | true

	@date