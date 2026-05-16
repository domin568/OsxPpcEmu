/**
 * Author:    domin568
 * Created:   16.05.2026
 * Brief:     redirected API declarations
 **/
#pragma once

namespace import::callback
{
using CallbackPtr = bool ( * )( ShimContext &ctx );
#define callback( name ) bool name( ShimContext &ctx );
callback( clock );
callback( setlocale );
callback( snprintf );
callback( strncat );
callback( keymgr_dwarf2_register_sections );
callback( cthread_init_routine );
callback( abs );
callback( atexit );
callback( atoi );
callback( bsearch );
callback( chmod );
callback( execve );
callback( exit );
callback( fclose );
callback( fwrite );
callback( fflush );
callback( fgetc );
callback( fopen );
callback( fork );
callback( fprintf );
callback( fstat );
callback( ioctl );
callback( malloc );
callback( calloc );
callback( memcpy );
callback( memmove );
callback( memset );
callback( printf );
callback( puts );
callback( qsort );
callback( setvbuf );
callback( signal );
callback( sprintf );
callback( vsprintf );
callback( stat );
callback( strcat );
callback( strchr );
callback( strcpy );
callback( strdup );
callback( strerror );
callback( strlen );
callback( strpbrk );
callback( strrchr );
callback( strstr );
callback( strtod );
callback( strtol );
callback( strncpy );
callback( vsnprintf );
callback( getcwd );
callback( free );
callback( strcmp );
callback( strncmp );
callback( fprintf );
callback( getenv );
callback( ___error );
callback( ___isctype );
callback( ___istype );
callback( ___tolower );
callback( ___toupper );
callback( _setjmp );
callback( _longjmp );
callback( realloc );
callback( readlink );
callback( lseek );
callback( open );
callback( close );
callback( read );
callback( write );
callback( memcmp );
callback( time );
callback( times );
callback( tmpnam );
callback( getdtablesize );
callback( localtime );
callback( lstat );
callback( umask );
callback( gethostbyname );
callback( gethostname );
callback( sscanf );
callback( ungetc );
callback( mktime );
callback( opendir );
callback( readdir );
callback( closedir );
callback( unlink );
callback( utime );
} // namespace import::callback