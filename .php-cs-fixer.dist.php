<?php

return (new PhpCsFixer\Config())
    ->setRules([
        '@PSR2' => true,
        'concat_space' => ['spacing' => 'one'],
        'no_unused_imports' => true,
        'ordered_imports' => true,
        'new_with_braces' => true,
        'method_argument_space' => false,
        'whitespace_after_comma_in_array' => true,
        'return_type_declaration' => [
            'space_before' => 'none'
        ],
        'single_quote' => true,
        'native_function_invocation' => [
            'strict' => false
        ],
        'nullable_type_declaration' => [
            'syntax' => 'question_mark',
        ],
        'nullable_type_declaration_for_default_null_value' => true,
    ])
    ->setFinder(
        PhpCsFixer\Finder::create()
            ->in(__DIR__)
    )
;
