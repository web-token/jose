<?php

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__.'/src',
        __DIR__.'/performance',
    ])
;

return PhpCsFixer\Config::create()
    ->setUsingCache(false)
    ->setRules([
        '@PSR1' => true,
        '@PSR2' => true,
        '@Symfony' => true,
        'array_syntax' => ['syntax' => 'short'],
        'binary_operator_spaces' => ['align_double_arrow' => true],
        'linebreak_after_opening_tag' => true,
        'not_operator_with_successor_space' => true,
        'ordered_imports' => true,
        'phpdoc_order' => true,
    ])
    ->setFinder($finder)
;
