bin_PROGRAMS = ttyspy
ttyspy_SOURCES = ttyspy.c \
		cfg_parser.c \
		cfg_parser.h \
		cfg_tokenizer.c \
		cfg_tokenizer.h \
		config.c \
		config.h
ttyspy_CPPFLAGS = $(LIBCURL_CPPFLAGS)
ttyspy_LDADD = $(LIBUTIL) $(LIBCURL)
