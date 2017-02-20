# HITCH_SEARCH_LIBS(VAR, LIBS, FUNC, NOTFOUND)
# --------------------------------------------
AC_DEFUN([HITCH_SEARCH_LIBS], [
	hitch_save_LIBS="${LIBS}"
	LIBS=""
	AC_SEARCH_LIBS([$3], [$2], [], [$4])
	AC_SUBST([$1_LIBS], [$LIBS])
	LIBS="${hitch_save_LIBS}"
])

# _HITCH_CHECK_FLAG(VAR, FLAG)
------------------------------
AC_DEFUN([_HITCH_CHECK_FLAG], [

	AC_MSG_CHECKING([whether the compiler accepts $2])
	_cflags="$CFLAGS"
	CFLAGS="[$]$1 $2 $CFLAGS"
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([int main(void) { return (0); }])],
		[AC_MSG_RESULT([yes]); $1="[$]$1 $2"],
		[AC_MSG_RESULT([no])])
	CFLAGS="$_cflags"
])

# HITCH_CHECK_FLAGS(VAR, FLAGS)
-------------------------------
AC_DEFUN([HITCH_CHECK_FLAGS], [

	m4_foreach([_flag],
		m4_split(m4_normalize([$2])),
			[_HITCH_CHECK_FLAG([$1], _flag)])

])
