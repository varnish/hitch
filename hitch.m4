# HITCH_SEARCH_LIBS(VAR, LIBS, FUNC, NOTFOUND)
# --------------------------------------------
AC_DEFUN([HITCH_SEARCH_LIBS], [
	hitch_save_LIBS="${LIBS}"
	LIBS=""
	AC_SEARCH_LIBS([$3], [$2], [], [$4])
	AC_SUBST([$1_LIBS], [$LIBS])
	AM_CONDITIONAL([HAVE_LIB_$1], [test "$1_LIBS" != no])
	LIBS="${hitch_save_LIBS}"
])
