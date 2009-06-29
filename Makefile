
ERLC = erlc
ERL = erl
SOURCES=*.erl
BUILD=build

all: compile

compile: $(SOURCES)
	[ -d $(BUILD) ] || mkdir $(BUILD)
	$(ERLC) -o $(BUILD) $(SOURCES)

run: all
	$(ERL) -pz $(BUILD) -run pcap parse dhcp.pcap -run init stop -noshell

clean:
	rm -rf $(BUILD) erl_crash.dump
