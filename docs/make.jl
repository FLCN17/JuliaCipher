using Documenter, JuliaCipher

#makedocs()

makedocs(
    ...,
    format = :html,
    sitename = "JuliaCipher",
)

deploydocs(
    repo   = "github.com/FLCN/JuliaCipher.jl.git",
    target = "build",
    deps   = nothing,
    make   = nothing
)
