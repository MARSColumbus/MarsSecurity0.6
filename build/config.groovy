
withConfig(configuration) {
    inline(phase: 'CONVERSION') { source, context, classNode ->
        classNode.putNodeMetaData('projectVersion', '8.0')
        classNode.putNodeMetaData('projectName', 'MarsSecurity')
        classNode.putNodeMetaData('isPlugin', 'true')
    }
}
