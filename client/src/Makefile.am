bin_PROGRAMS = ttyspy
sbin_PROGRAMS = ttyspyd
ttyspy_SOURCES = ttyspy.c \
		cfg_parser.c \
		cfg_parser.h \
		cfg_tokenizer.c \
		cfg_tokenizer.h \
		config.c \
		config.h \
		strlcpy.c \
		ttyspy_protocol.h
ttyspy_LDADD = $(LIBUTIL)
ttyspyd_SOURCES = ttyspyd.c \
		cfg_parser.c \
		cfg_parser.h \
		cfg_tokenizer.c \
		cfg_tokenizer.h \
		config.c \
		config.h \
		setproctitle.c \
		strlcpy.c \
		ttyspy_protocol.h
ttyspyd_CPPFLAGS = $(LIBCURL_CPPFLAGS)
ttyspyd_LDADD = $(LIBCURL)
